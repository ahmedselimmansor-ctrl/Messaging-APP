package chat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/cassandrax"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/redisx"
)

// historyMessage is the client-facing shape of a message.
type historyMessage struct {
	MessageID  string           `json:"message_id"`
	ChatID     int64            `json:"chat_id"`
	Seq        int64            `json:"seq"`
	SenderID   int64            `json:"sender_id"`
	Type       string           `json:"type"`
	Body       string           `json:"body,omitempty"`
	Encrypted  bool             `json:"encrypted,omitempty"`
	Media      *events.MediaRef `json:"media,omitempty"`
	ReplyToSeq int64            `json:"reply_to_seq,omitempty"`
	Date       time.Time        `json:"date"`
	EditedAt   *time.Time       `json:"edited_at,omitempty"`
	Deleted    bool             `json:"deleted,omitempty"`
}

func toHistoryMessage(e *events.MessageEvent) historyMessage {
	return historyMessage{
		MessageID: e.MessageID, ChatID: e.ChatID, Seq: e.Seq, SenderID: e.SenderID,
		Type: string(e.Type), Body: e.Body, Encrypted: e.Encrypted, Media: e.Media,
		ReplyToSeq: e.ReplyToSeq, Date: e.CreatedAt,
	}
}

func fromStored(m cassandrax.StoredMessage) historyMessage {
	out := historyMessage{
		MessageID: m.MessageID, ChatID: m.ChatID, Seq: m.Seq, SenderID: m.SenderID,
		Type: m.Type, Body: m.Body, Encrypted: m.Encrypted, ReplyToSeq: m.ReplyToSeq,
		Date: m.CreatedAt, EditedAt: m.EditedAt, Deleted: m.Deleted,
	}
	if m.MediaJSON != "" && m.MediaJSON != "{}" {
		var ref events.MediaRef
		if err := json.Unmarshal([]byte(m.MediaJSON), &ref); err == nil {
			out.Media = &ref
		}
	}
	// A deleted message keeps its slot in the sequence so the client's
	// cursors stay valid, but carries no content.
	if m.Deleted {
		out.Body = ""
		out.Media = nil
	}
	return out
}

// ---------------------------------------------------------------------------
// Chat management
// ---------------------------------------------------------------------------

type createChatRequest struct {
	// Type is private, group or channel.
	Type string `json:"type"`
	// PeerID is required for a private chat.
	PeerID int64 `json:"peer_id,omitempty"`
	// Title is required for a group or channel.
	Title string `json:"title,omitempty"`
	// Members is the initial roster for a group or channel.
	Members []int64 `json:"members,omitempty"`
}

func (s *Service) handleCreateChat(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	var req createChatRequest
	if err := httpx.DecodeJSON(r, 256<<10, &req); err != nil {
		return err
	}

	switch pgstore.ChatType(req.Type) {
	case pgstore.ChatPrivate:
		if req.PeerID == 0 {
			return httpx.ErrBadRequest("peer_id is required for a private chat")
		}
		if req.PeerID == claims.UserID {
			return httpx.ErrBadRequest("you cannot start a private chat with yourself")
		}
		if _, err := s.Users.GetByID(r.Context(), req.PeerID); err != nil {
			return httpx.ErrNotFound("no such user")
		}

		chat, created, err := s.Chats.CreatePrivate(r.Context(), s.IDs.Next(), claims.UserID, req.PeerID, s.HomeRegionFor())
		if err != nil {
			return httpx.ErrInternal("could not create the chat").WithCause(err)
		}
		if created {
			s.invalidateMembers(r.Context(), chat.ID)
			s.notifyChatCreated(r.Context(), chat, []int64{claims.UserID, req.PeerID})
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"chat": chat, "created": created})
		return nil

	case pgstore.ChatGroup, pgstore.ChatChannel:
		title := strings.TrimSpace(req.Title)
		if title == "" || len([]rune(title)) > 128 {
			return httpx.ErrBadRequest("title must be 1..128 characters")
		}
		if len(req.Members) > 1000 {
			return httpx.ErrBadRequest("at most 1000 members at creation; add the rest afterwards")
		}

		chat, err := s.Chats.CreateGroup(r.Context(), s.IDs.Next(),
			pgstore.ChatType(req.Type), title, claims.UserID, req.Members, s.HomeRegionFor())
		if err != nil {
			return httpx.ErrInternal("could not create the chat").WithCause(err)
		}

		roster := append([]int64{claims.UserID}, req.Members...)
		s.invalidateMembers(r.Context(), chat.ID)
		s.notifyChatCreated(r.Context(), chat, roster)

		httpx.WriteJSON(w, http.StatusOK, map[string]any{"chat": chat, "created": true})
		return nil
	}

	return httpx.ErrBadRequest("type must be private, group or channel")
}

func (s *Service) handleGetChat(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	if _, err := s.requireMember(r.Context(), chatID, claims.UserID); err != nil {
		return err
	}

	chat, err := s.Chats.Get(r.Context(), chatID)
	if err != nil {
		return httpx.ErrNotFound("no such chat")
	}
	httpx.WriteJSON(w, http.StatusOK, chat)
	return nil
}

type updateChatRequest struct {
	Title       *string `json:"title,omitempty"`
	Description *string `json:"description,omitempty"`
	PhotoObject *string `json:"photo_object,omitempty"`
}

func (s *Service) handleUpdateChat(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	var req updateChatRequest
	if err := httpx.DecodeJSON(r, 16<<10, &req); err != nil {
		return err
	}

	member, err := s.requireMember(r.Context(), chatID, claims.UserID)
	if err != nil {
		return err
	}
	if member.Role != pgstore.RoleOwner && member.Role != pgstore.RoleAdmin {
		return httpx.ErrForbidden("only owners and admins can change chat settings")
	}
	if req.Title != nil {
		t := strings.TrimSpace(*req.Title)
		if t == "" || len([]rune(t)) > 128 {
			return httpx.ErrBadRequest("title must be 1..128 characters")
		}
		req.Title = &t
	}

	chat, err := s.Chats.UpdateMeta(r.Context(), chatID, req.Title, req.Description, req.PhotoObject)
	if err != nil {
		return httpx.ErrInternal("could not update the chat").WithCause(err)
	}
	httpx.WriteJSON(w, http.StatusOK, chat)
	return nil
}

func (s *Service) handleListMembers(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	if _, err := s.requireMember(r.Context(), chatID, claims.UserID); err != nil {
		return err
	}

	ids, err := s.Members.IDs(r.Context(), chatID)
	if err != nil {
		return httpx.ErrInternal("member lookup failed").WithCause(err)
	}
	// Cap the hydrated roster: a channel with 200k subscribers must not
	// produce a 200k-element JSON response.
	const maxHydrated = 500
	page := ids
	if len(page) > maxHydrated {
		page = page[:maxHydrated]
	}
	users, err := s.Users.GetMany(r.Context(), page)
	if err != nil {
		return httpx.ErrInternal("user lookup failed").WithCause(err)
	}

	out := make([]pgstore.User, 0, len(page))
	for _, id := range page {
		if u, ok := users[id]; ok {
			out = append(out, u)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"members":   out,
		"total":     len(ids),
		"truncated": len(ids) > maxHydrated,
	})
	return nil
}

// handleListMemberIDs is the internal, unhydrated variant the gateway uses to
// decide which pub/sub channels to subscribe to.
func (s *Service) handleListMemberIDs(w http.ResponseWriter, r *http.Request) error {
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	ids, err := s.Members.IDs(r.Context(), chatID)
	if err != nil {
		return httpx.ErrInternal("member lookup failed").WithCause(err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"member_ids": ids})
	return nil
}

type addMemberRequest struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role,omitempty"`
}

func (s *Service) handleAddMember(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	var req addMemberRequest
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		return err
	}
	if req.UserID == 0 {
		return httpx.ErrBadRequest("user_id is required")
	}

	member, err := s.requireMember(r.Context(), chatID, claims.UserID)
	if err != nil {
		return err
	}
	chat, err := s.Chats.Get(r.Context(), chatID)
	if err != nil {
		return httpx.ErrNotFound("no such chat")
	}
	if chat.Type == pgstore.ChatPrivate {
		return httpx.ErrBadRequest("a private chat cannot gain members")
	}
	if member.Role != pgstore.RoleOwner && member.Role != pgstore.RoleAdmin {
		return httpx.ErrForbidden("only owners and admins can add members")
	}
	if chat.MemberCount >= s.Cfg.MaxGroupMembers {
		return httpx.ErrConflict("this chat has reached its member limit of %d", s.Cfg.MaxGroupMembers)
	}
	if _, err := s.Users.GetByID(r.Context(), req.UserID); err != nil {
		return httpx.ErrNotFound("no such user")
	}

	role := pgstore.MemberRole(orDefault(req.Role, string(pgstore.RoleMember)))
	switch role {
	case pgstore.RoleMember, pgstore.RoleAdmin, pgstore.RoleRestricted:
	default:
		return httpx.ErrBadRequest("role must be member, admin or restricted")
	}

	if err := s.Members.Add(r.Context(), chatID, req.UserID, role); err != nil {
		return httpx.ErrInternal("could not add the member").WithCause(err)
	}
	s.invalidateMembers(r.Context(), chatID)
	s.publishUpdate(r.Context(), chatID, redisx.Update{
		Kind: redisx.UpdateMemberChanged, ChatID: chatID, UserID: req.UserID,
	})
	s.audit(r.Context(), r, auditlog.Entry{
		Action:     auditlog.ActionMemberAdded,
		ActorID:    claims.UserID,
		TargetType: "user",
		TargetID:   req.UserID,
		Detail: map[string]string{
			"chat_id": strconv.FormatInt(chatID, 10),
			"role":    string(role),
		},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"added": true})
	return nil
}

func (s *Service) handleRemoveMember(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	targetID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}

	member, err := s.requireMember(r.Context(), chatID, claims.UserID)
	if err != nil {
		return err
	}
	target, err := s.Members.Get(r.Context(), chatID, targetID)
	if err != nil {
		return httpx.ErrNotFound("that user is not a member")
	}
	if err := canRemoveMember(member, target); err != nil {
		return err
	}

	if err := s.Members.Remove(r.Context(), chatID, targetID); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return httpx.ErrNotFound("that user is not a member")
		}
		return httpx.ErrInternal("could not remove the member").WithCause(err)
	}
	s.invalidateMembers(r.Context(), chatID)
	s.publishUpdate(r.Context(), chatID, redisx.Update{
		Kind: redisx.UpdateMemberChanged, ChatID: chatID, UserID: targetID,
	})
	s.audit(r.Context(), r, auditlog.Entry{
		Action:     auditlog.ActionMemberRemoved,
		ActorID:    claims.UserID,
		TargetType: "user",
		TargetID:   targetID,
		Detail: map[string]string{
			"chat_id":     strconv.FormatInt(chatID, 10),
			"actor_role":  string(member.Role),
			"target_role": string(target.Role),
		},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"removed": true})
	return nil
}

func (s *Service) handleLeave(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}

	member, err := s.requireMember(r.Context(), chatID, claims.UserID)
	if err != nil {
		return err
	}
	if member.Role == pgstore.RoleOwner {
		return httpx.ErrConflict("transfer ownership before leaving this chat")
	}

	if err := s.Members.Remove(r.Context(), chatID, claims.UserID); err != nil {
		return httpx.ErrInternal("could not leave the chat").WithCause(err)
	}
	s.invalidateMembers(r.Context(), chatID)

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"left": true})
	return nil
}

type muteRequest struct {
	// MutedForSeconds of 0 unmutes; a negative value mutes indefinitely.
	MutedForSeconds int   `json:"muted_for_seconds"`
	Pinned          *bool `json:"pinned,omitempty"`
	Archived        *bool `json:"archived,omitempty"`
}

func (s *Service) handleMute(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	var req muteRequest
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		return err
	}
	if _, err := s.requireMember(r.Context(), chatID, claims.UserID); err != nil {
		return err
	}

	var until *time.Time
	switch {
	case req.MutedForSeconds < 0:
		// "Forever" is 100 years, which keeps the column a plain timestamp
		// instead of a nullable-with-special-meaning.
		t := time.Now().AddDate(100, 0, 0)
		until = &t
	case req.MutedForSeconds > 0:
		t := time.Now().Add(time.Duration(req.MutedForSeconds) * time.Second)
		until = &t
	}
	if err := s.Members.SetMuted(r.Context(), chatID, claims.UserID, until); err != nil {
		return httpx.ErrInternal("could not update mute settings").WithCause(err)
	}
	if req.Pinned != nil || req.Archived != nil {
		if err := s.Members.SetFlags(r.Context(), chatID, claims.UserID, req.Pinned, req.Archived); err != nil {
			return httpx.ErrInternal("could not update chat flags").WithCause(err)
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"muted_until": until})
	return nil
}

// invalidateMembers drops the cached roster after a membership change.
//
// It runs detached from the request: the membership write has already
// committed, and a slow Redis must not turn a successful "add member" into a
// failed one. The context is inherited only for its trace, not its
// cancellation, so the invalidation completes even if the client hangs up —
// leaving a stale roster cached would let a removed member keep posting.
func (s *Service) invalidateMembers(ctx context.Context, chatID int64) {
	detached := context.WithoutCancel(ctx)
	go func() {
		bg, cancel := context.WithTimeout(detached, 3*time.Second)
		defer cancel()
		if err := s.MemCache.Invalidate(bg, chatID); err != nil {
			s.Log.Warn("member cache invalidation failed", "chat_id", chatID, "error", err)
		}
	}()
}

func (s *Service) notifyChatCreated(ctx context.Context, chat pgstore.Chat, members []int64) {
	payload, err := json.Marshal(chat)
	if err != nil {
		return
	}
	detached := context.WithoutCancel(ctx)
	go func() {
		bg, cancel := context.WithTimeout(detached, 3*time.Second)
		defer cancel()
		if err := s.Bus.PublishToUsers(bg, members, redisx.Update{
			Kind: redisx.UpdateChatCreated, ChatID: chat.ID, Body: payload,
		}); err != nil {
			s.Log.Warn("chat-created fanout failed", "chat_id", chat.ID, "error", err)
		}
	}()
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

type setRoleRequest struct {
	// Role is member, admin or restricted. Ownership is not transferable
	// through this endpoint — see the note below.
	Role string `json:"role"`
}

// handleSetRole changes an existing member's role.
//
// The rules here are the ones that stop a chat being taken over, and they are
// deliberately stricter than "admins can administrate":
//
//   - Only the owner may create or remove admins. If admins could promote each
//     other, one compromised admin account escalates to controlling the chat.
//   - Nobody may change the owner's role, including the owner. Demoting the
//     owner would leave a chat with no owner and no way to appoint one.
//   - Nobody may set the owner role. A chat has exactly one owner and transfer
//     is a distinct operation that must move it rather than add a second.
//   - You cannot change your own role. Otherwise an admin demoting themselves
//     by accident is unrecoverable without an owner, and a restricted member
//     could not be prevented from trying the reverse.
func (s *Service) handleSetRole(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	targetID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}
	var req setRoleRequest
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		return err
	}

	role := pgstore.MemberRole(req.Role)

	actor, err := s.requireMember(r.Context(), chatID, claims.UserID)
	if err != nil {
		return err
	}
	target, err := s.Members.Get(r.Context(), chatID, targetID)
	if err != nil {
		return httpx.ErrNotFound("that user is not a member")
	}
	// The privilege rules live in authz.go, where they can be tested without
	// four databases. See canSetRole for why each one exists.
	if err := canSetRole(actor, target, role); err != nil {
		return err
	}

	if target.Role == role {
		// Idempotent, and worth short-circuiting so a retry does not produce a
		// second audit entry implying a second change.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"role": role, "changed": false})
		return nil
	}

	if err := s.Members.SetRole(r.Context(), chatID, targetID, role); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return httpx.ErrNotFound("that user is not a member")
		}
		return httpx.ErrInternal("could not change the role").WithCause(err)
	}

	s.invalidateMembers(r.Context(), chatID)
	s.publishUpdate(r.Context(), chatID, redisx.Update{
		Kind: redisx.UpdateMemberChanged, ChatID: chatID, UserID: targetID,
	})
	s.audit(r.Context(), r, auditlog.Entry{
		Action:     auditlog.ActionRoleChanged,
		ActorID:    claims.UserID,
		TargetType: "user",
		TargetID:   targetID,
		Detail: map[string]string{
			"chat_id":    strconv.FormatInt(chatID, 10),
			"actor_role": string(actor.Role),
			"from":       string(target.Role),
			"to":         string(role),
		},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"role": role, "changed": true})
	return nil
}

// handleDeleteChat deletes a chat.
//
// Owner only, and soft — the row is marked rather than removed. Two reasons:
// message history in Cassandra is keyed by chat id and a hard delete would
// leave it orphaned rather than cleaned, and a deletion that turns out to be a
// mistake or a compromised account is recoverable for as long as the row
// survives.
//
// A private chat cannot be deleted by one participant. Doing so would destroy
// the other person's copy of a conversation they equally own; leaving is the
// right operation, and archiving is the right one for "I do not want to see
// this".
func (s *Service) handleDeleteChat(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}

	member, err := s.requireMember(r.Context(), chatID, claims.UserID)
	if err != nil {
		return err
	}
	chat, err := s.Chats.Get(r.Context(), chatID)
	if err != nil {
		return httpx.ErrNotFound("no such chat")
	}
	if err := canDeleteChat(member, chat); err != nil {
		return err
	}

	// Capture the roster before deleting: afterwards there is nobody to tell.
	recipients, err := s.Members.IDs(r.Context(), chatID)
	if err != nil {
		s.Log.Warn("could not read the roster before deleting a chat; clients will find out on reconnect",
			"chat_id", chatID, "error", err)
	}

	if err := s.Chats.SoftDelete(r.Context(), chatID); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return httpx.ErrNotFound("no such chat")
		}
		return httpx.ErrInternal("could not delete the chat").WithCause(err)
	}

	s.invalidateMembers(r.Context(), chatID)
	s.publishUpdate(r.Context(), chatID, redisx.Update{
		Kind: redisx.UpdateChatDeleted, ChatID: chatID, UserID: claims.UserID,
	})
	s.audit(r.Context(), r, auditlog.Entry{
		Action:     auditlog.ActionChatDeleted,
		ActorID:    claims.UserID,
		TargetType: "chat",
		TargetID:   chatID,
		Detail: map[string]string{
			"chat_type": string(chat.Type),
			"members":   strconv.Itoa(len(recipients)),
			"title":     chat.Title,
		},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	return nil
}
