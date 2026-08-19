package chat

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
)

// Data export.
//
// GDPR Article 20 and equivalents elsewhere give a person the right to a copy
// of their data in a machine-readable form. For a messaging platform that
// right has an awkward edge, and how it is handled is the interesting part of
// this file.
//
// A conversation is not one person's data. Every message in a private chat was
// written by one of two people and read by both, and both have a claim to a
// copy. So the export includes:
//
//   - Everything about the requester: profile, devices, contacts, settings.
//   - Every message the requester *sent*, in full.
//   - For messages sent by others: the fact of them, their timing, and who
//     sent them — but not their content.
//
// That last decision is the one worth defending. Including other people's
// message bodies would mean any user can extract their correspondents'
// writing in bulk simply by asking, which turns a privacy right into a
// disclosure mechanism. Excluding the content while keeping the structure
// preserves what the requester needs to understand their own history — when
// they talked to whom, and what they said — without handing over someone
// else's words.
//
// Secret chats appear as metadata only, and not because of policy: the server
// holds ciphertext it cannot decrypt. The export says so explicitly rather
// than silently omitting them, so a person who checks does not conclude their
// history was lost.

// exportEnvelope is the top-level structure of an export.
type exportEnvelope struct {
	// Format is versioned so a future change is detectable by a tool reading
	// an old file.
	Format      string    `json:"format"`
	GeneratedAt time.Time `json:"generated_at"`

	// Notes tells the person what is and is not here, in their file rather
	// than only in documentation they will not read.
	Notes []string `json:"notes"`

	User     json.RawMessage `json:"user"`
	Devices  []exportDevice  `json:"devices"`
	Contacts []int64         `json:"contact_user_ids"`
	Blocked  []int64         `json:"blocked_user_ids"`
	Chats    []exportChat    `json:"chats"`
	Messages []exportMessage `json:"messages"`
	Secret   []exportSecret  `json:"secret_chats"`
}

type exportDevice struct {
	ID         int64     `json:"id"`
	Platform   string    `json:"platform"`
	Model      string    `json:"model,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
}

type exportChat struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`
	Title     string    `json:"title,omitempty"`
	Role      string    `json:"your_role"`
	JoinedAt  time.Time `json:"joined_at"`
	MemberIDs []int64   `json:"member_user_ids,omitempty"`
}

type exportMessage struct {
	ChatID   int64     `json:"chat_id"`
	Seq      int64     `json:"seq"`
	SenderID int64     `json:"sender_id"`
	Date     time.Time `json:"date"`
	Type     string    `json:"type,omitempty"`

	// Mine distinguishes the two cases below at a glance.
	Mine bool `json:"sent_by_you"`
	// Body is present only for the requester's own messages. See the file
	// comment for why.
	Body string `json:"body,omitempty"`
	// Withheld explains an absent body, so the file is self-describing rather
	// than looking truncated.
	Withheld string `json:"content_withheld,omitempty"`
}

type exportSecret struct {
	ID        int64     `json:"id"`
	PeerID    int64     `json:"peer_user_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	Note      string    `json:"note"`
}

// handleExport builds and returns the requester's data.
//
// Synchronous, with a hard cap on how much history it will walk. A full export
// of a heavy user is a large read, and doing it inline bounds the damage: the
// request times out rather than a background job quietly consuming the cluster.
// The cap is disclosed in the file when it is hit, because an export that
// silently stops at 50,000 messages is worse than one that says it did.
func (s *Service) handleExport(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	ctx := r.Context()

	// The most expensive request the platform serves, and one nobody
	// legitimately makes twice in an hour.
	if err := s.checkLimit(ctx, ratelimit.KeyUser("export", claims.UserID), ratelimit.DataExport); err != nil {
		return err
	}

	out := exportEnvelope{
		Format:      "messaging.export.v1",
		GeneratedAt: time.Now().UTC(),
		Notes: []string{
			"Messages you sent are included in full.",
			"Messages other people sent to you are listed with their sender and timing, but not their text: their words are their data, not yours.",
			"Secret chats are end-to-end encrypted. The server holds only ciphertext it cannot read, so their contents cannot appear here — they exist only on your devices.",
			"Media is listed by reference. Download links are available through the app for as long as the files are retained.",
		},
	}

	user, err := s.Users.GetByID(ctx, claims.UserID)
	if err != nil {
		return httpx.ErrNotFound("account not found")
	}
	if out.User, err = json.Marshal(user); err != nil {
		return httpx.ErrInternal("could not encode the profile").WithCause(err)
	}

	// Dialogs define which chats to walk. includeArchived is true: an archived
	// chat is still the person's data, and an export that quietly omitted it
	// would be incomplete in a way nobody could detect.
	dialogs, err := s.Members.Dialogs(ctx, claims.UserID, true, 1000, 0)
	if err != nil {
		return httpx.ErrInternal("could not list your chats").WithCause(err)
	}

	const maxMessages = 50_000
	truncated := false

	for _, d := range dialogs {
		ec := exportChat{
			ID:       d.Chat.ID,
			Type:     string(d.Chat.Type),
			Title:    d.Chat.Title,
			Role:     string(d.Role),
			JoinedAt: d.Chat.CreatedAt,
		}
		// Member ids only for group chats. In a private chat the other party
		// is already evident from the messages, and listing the roster of a
		// large channel would balloon the file for no benefit.
		if d.Chat.Type != pgstore.ChatPrivate {
			if ids, err := s.Members.IDs(ctx, d.Chat.ID); err == nil && len(ids) <= 1000 {
				ec.MemberIDs = ids
			}
		}
		out.Chats = append(out.Chats, ec)

		if len(out.Messages) >= maxMessages {
			truncated = true
			continue
		}

		msgs, err := s.Messages.History(ctx, d.Chat.ID, 0, maxMessages-len(out.Messages))
		if err != nil {
			// One unreadable chat must not fail the whole export. Note it and
			// continue — a partial export the person can see is better than an
			// error they cannot act on.
			s.Log.Warn("could not read a chat for an export", "chat_id", d.Chat.ID, "error", err)
			out.Notes = append(out.Notes,
				fmt.Sprintf("Chat %d could not be read when this export was generated.", d.Chat.ID))
			continue
		}

		for _, m := range msgs {
			em := exportMessage{
				ChatID:   d.Chat.ID,
				Seq:      m.Seq,
				SenderID: m.SenderID,
				Date:     m.CreatedAt,
				Type:     m.Type,
				Mine:     m.SenderID == claims.UserID,
			}
			switch {
			case m.Deleted:
				em.Withheld = "deleted"
			case m.Encrypted:
				em.Withheld = "end-to-end encrypted; the server cannot read it"
			case em.Mine:
				em.Body = m.Body
			default:
				em.Withheld = "sent by another person; their content is their data"
			}
			out.Messages = append(out.Messages, em)
		}
	}

	if truncated {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"This export was capped at %d messages and is incomplete. Contact support for a full archive.",
			maxMessages))
	}

	// Contacts, as user ids rather than the stored names. The names in a
	// contact list are the requester's own labels for other people, so those
	// are theirs to have — but the list is also the single most sensitive
	// derived thing here, so it stays minimal.
	if contacts, err := s.Contacts.List(ctx, claims.UserID, 5000, 0); err == nil {
		for _, c := range contacts {
			out.Contacts = append(out.Contacts, c.UserID)
		}
	} else {
		s.Log.Warn("could not read contacts for an export", "error", err)
		out.Notes = append(out.Notes, "Your contact list could not be read when this export was generated.")
	}

	if blocked, err := s.Blocks.List(ctx, claims.UserID); err == nil {
		out.Blocked = blocked
	}

	// Secret chats: metadata only, and the note says why rather than leaving
	// someone to conclude their history was lost.
	if secrets, err := s.SecretChats.ListFor(ctx, claims.UserID); err == nil {
		for _, sc := range secrets {
			peer := sc.ParticipantID
			if peer == claims.UserID {
				peer = sc.AdminID
			}
			out.Secret = append(out.Secret, exportSecret{
				ID:        sc.ID,
				PeerID:    peer,
				State:     sc.State,
				CreatedAt: sc.CreatedAt,
				Note:      "end-to-end encrypted; the server holds no key and cannot produce the contents",
			})
		}
	}

	if devices, err := s.Devices.ListForUser(ctx, claims.UserID); err == nil {
		for _, d := range devices {
			// Revoked sessions are included: "which devices have had access to
			// my account, and when" is exactly the question this answers.
			out.Devices = append(out.Devices, exportDevice{
				ID: d.ID, Platform: d.Platform, Model: d.DeviceModel,
				CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt,
			})
		}
	}

	// Audited. A data export is a bulk read of an account's history, and it is
	// the request an attacker with a stolen session would make first — so the
	// record of it is what lets the real owner see that it happened.
	s.audit(ctx, r, auditlog.Entry{
		Action:     auditlog.ActionDataExport,
		ActorID:    claims.UserID,
		ActorType:  "user",
		TargetType: "user",
		TargetID:   claims.UserID,
		Detail: map[string]string{
			"chats":     fmt.Sprint(len(out.Chats)),
			"messages":  fmt.Sprint(len(out.Messages)),
			"truncated": fmt.Sprint(truncated),
		},
	})

	// An attachment, so a browser saves it rather than rendering a very large
	// JSON document.
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="messaging-export-%d.json"`, claims.UserID))
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}
