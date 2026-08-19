package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
)

// Contacts and the blocklist live in the auth service because they are
// properties of an account rather than of a conversation, and because the
// contact-import path needs the phone column that only this service may read.

// contactImportLimit is deliberately tight.
//
// Import is the one endpoint that answers "is this phone number registered?",
// in bulk. Without a hard limit it becomes a directory-enumeration tool: an
// attacker walks a country's number range a thousand at a time and learns who
// has an account.
var contactImportLimit = ratelimit.Limit{Burst: 3, Rate: 1.0 / 600.0} // 3, then one per 10 minutes

// maxImportEntries bounds one request. A real address book is hundreds of
// entries; tens of thousands is enumeration.
const maxImportEntries = 2000

type importContactsRequest struct {
	Contacts []pgstore.ImportEntry `json:"contacts"`
}

func (s *Service) handleImportContacts(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}

	var req importContactsRequest
	// A 2000-entry address book of base64 hashes is roughly 120KB.
	if err := httpx.DecodeJSON(r, 512<<10, &req); err != nil {
		return err
	}
	if len(req.Contacts) == 0 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"users": []pgstore.User{}})
		return nil
	}
	if len(req.Contacts) > maxImportEntries {
		return httpx.ErrBadRequest("at most %d contacts per request", maxImportEntries)
	}

	if err := s.checkLimit(r.Context(),
		ratelimit.KeyUser("contact_import", userID), contactImportLimit); err != nil {
		return err
	}

	matched, err := s.Contacts.Import(r.Context(), userID, s.Cfg.ContactPepper, req.Contacts)
	if err != nil {
		return httpx.ErrInternal("contact import failed").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"users": matched,
		"total": len(matched),
	})
	return nil
}

func (s *Service) handleListContacts(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}

	contacts, err := s.Contacts.List(r.Context(), userID,
		httpx.QueryInt(r, "limit", 200, 1, 1000),
		httpx.QueryInt(r, "offset", 0, 0, 100_000))
	if err != nil {
		return httpx.ErrInternal("contact lookup failed").WithCause(err)
	}

	// Hydrate the profiles in one batch rather than one query per contact.
	ids := make([]int64, 0, len(contacts))
	for _, c := range contacts {
		ids = append(ids, c.UserID)
	}
	users, err := s.Users.GetMany(r.Context(), ids)
	if err != nil {
		return httpx.ErrInternal("user lookup failed").WithCause(err)
	}

	type entry struct {
		UserID      int64   `json:"user_id"`
		FirstName   string  `json:"first_name"`
		LastName    string  `json:"last_name,omitempty"`
		DisplayName string  `json:"display_name"`
		Username    *string `json:"username,omitempty"`
		AvatarObj   *string `json:"avatar_object,omitempty"`
	}
	out := make([]entry, 0, len(contacts))
	for _, c := range contacts {
		u, ok := users[c.UserID]
		if !ok {
			continue
		}
		out = append(out, entry{
			UserID: c.UserID, FirstName: c.FirstName, LastName: c.LastName,
			DisplayName: u.DisplayName, Username: u.Username, AvatarObj: u.AvatarObj,
		})
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"contacts": out})
	return nil
}

type addContactRequest struct {
	UserID    int64  `json:"user_id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
}

func (s *Service) handleAddContact(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	var req addContactRequest
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		return err
	}
	if req.UserID == 0 {
		return httpx.ErrBadRequest("user_id is required")
	}
	if strings.TrimSpace(req.FirstName) == "" {
		return httpx.ErrBadRequest("first_name is required")
	}
	if _, err := s.Users.GetByID(r.Context(), req.UserID); err != nil {
		return httpx.ErrNotFound("no such user")
	}

	if err := s.Contacts.Add(r.Context(), userID, req.UserID,
		strings.TrimSpace(req.FirstName), strings.TrimSpace(req.LastName)); err != nil {
		if errors.Is(err, pgstore.ErrConflict) {
			return httpx.ErrBadRequest("you cannot add yourself as a contact")
		}
		return httpx.ErrInternal("could not save the contact").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"added": true})
	return nil
}

func (s *Service) handleDeleteContact(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	contactID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}

	if err := s.Contacts.Delete(r.Context(), userID, contactID); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return httpx.ErrNotFound("no such contact")
		}
		return httpx.ErrInternal("could not delete the contact").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	return nil
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

type blockRequest struct {
	UserID int64 `json:"user_id"`
}

func (s *Service) handleBlock(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	var req blockRequest
	if err := httpx.DecodeJSON(r, 1<<10, &req); err != nil {
		return err
	}
	if req.UserID == 0 {
		return httpx.ErrBadRequest("user_id is required")
	}

	if err := s.Blocks.Block(r.Context(), userID, req.UserID); err != nil {
		if errors.Is(err, pgstore.ErrConflict) {
			return httpx.ErrBadRequest("you cannot block yourself")
		}
		return httpx.ErrInternal("could not block the user").WithCause(err)
	}

	// Blocking is a rare, deliberate action, so invalidating the cache
	// eagerly is cheap and means the next message is stopped rather than the
	// one after the TTL expires.
	s.invalidateBlockCache(r.Context(), userID, req.UserID)

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"blocked": true})
	return nil
}

func (s *Service) handleUnblock(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	blockedID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}

	if err := s.Blocks.Unblock(r.Context(), userID, blockedID); err != nil {
		return httpx.ErrInternal("could not unblock the user").WithCause(err)
	}
	s.invalidateBlockCache(r.Context(), userID, blockedID)

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"unblocked": true})
	return nil
}

func (s *Service) handleListBlocks(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	ids, err := s.Blocks.List(r.Context(), userID)
	if err != nil {
		return httpx.ErrInternal("blocklist lookup failed").WithCause(err)
	}

	users, err := s.Users.GetMany(r.Context(), ids)
	if err != nil {
		return httpx.ErrInternal("user lookup failed").WithCause(err)
	}

	type blocked struct {
		UserID      int64   `json:"user_id"`
		DisplayName string  `json:"display_name"`
		Username    *string `json:"username,omitempty"`
	}
	out := make([]blocked, 0, len(ids))
	for _, id := range ids {
		if u, ok := users[id]; ok {
			out = append(out, blocked{UserID: id, DisplayName: u.DisplayName, Username: u.Username})
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"blocked": out})
	return nil
}

// handleBlockCheck is the internal endpoint the chat service calls on the
// send path of a private chat.
func (s *Service) handleBlockCheck(w http.ResponseWriter, r *http.Request) error {
	a := httpx.QueryInt64(r, "a", 0)
	b := httpx.QueryInt64(r, "b", 0)
	if a == 0 || b == 0 {
		return httpx.ErrBadRequest("both a and b are required")
	}

	blocked, err := s.Blocks.IsBlockedBetween(r.Context(), a, b)
	if err != nil {
		return httpx.ErrUnavailable("block lookup failed").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"blocked": blocked})
	return nil
}

// handleBlockedAmong filters a group's recipients down to those who have
// blocked the sender.
func (s *Service) handleBlockedAmong(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		SenderID   int64   `json:"sender_id"`
		Candidates []int64 `json:"candidates"`
	}
	if err := httpx.DecodeJSON(r, 256<<10, &req); err != nil {
		return err
	}
	if req.SenderID == 0 {
		return httpx.ErrBadRequest("sender_id is required")
	}
	if len(req.Candidates) > 10_000 {
		return httpx.ErrBadRequest("at most 10000 candidates per request")
	}

	blocked, err := s.Blocks.BlockedAmong(r.Context(), req.SenderID, req.Candidates)
	if err != nil {
		return httpx.ErrUnavailable("block lookup failed").WithCause(err)
	}

	ids := make([]int64, 0, len(blocked))
	for id := range blocked {
		ids = append(ids, id)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"blocked_by": ids})
	return nil
}

// blockCacheKey is the key the chat service caches a block decision under.
//
// The pair is ordered so both directions share one entry: a block is
// symmetric, so caching it twice would mean two chances to leave a stale one
// behind.
func blockCacheKey(a, b int64) string {
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("block:{%d:%d}", a, b)
}

func (s *Service) invalidateBlockCache(ctx context.Context, a, b int64) {
	if err := s.Redis.Raw().Del(ctx, blockCacheKey(a, b)).Err(); err != nil {
		s.Log.Warn("could not invalidate the block cache", "error", err)
	}
}
