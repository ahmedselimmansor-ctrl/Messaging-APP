package chat

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
)

// refuseIfBanned stops a banned account from sending.
//
// It fails *open* on a Redis error, deliberately. The authoritative ban check
// is at token issuance in the auth service, so a banned account cannot obtain
// new credentials at all; this check exists only to close the window where a
// ban lands while an access token is still valid. Failing closed here would
// mean a Redis outage silences the entire platform to enforce a rule that is
// already being enforced elsewhere — trading a bounded problem for a total
// one.
//
// The error is logged rather than swallowed, so a persistent failure is
// visible instead of quietly leaving the window open.
func (s *Service) refuseIfBanned(ctx context.Context, userID int64) error {
	if s.BanCache == nil {
		return nil
	}
	banned, err := s.BanCache.IsBanned(ctx, userID)
	if err != nil {
		s.Log.Error("could not check the ban list; allowing the send — "+
			"bans remain enforced at token issuance",
			"user_id", userID, "error", err)
		return nil
	}
	if banned {
		// Deliberately not "you are banned because X". The reason is between
		// the platform and its appeals process, and echoing it back here would
		// let an abuser probe which behaviour triggered it.
		return httpx.ErrForbidden("this account cannot send messages")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

type reportRequest struct {
	// SubjectID is the account being reported. Required — a report is always
	// about a person, even when it points at one of their messages.
	SubjectID int64 `json:"subject_id"`
	// ChatID and MessageSeq locate the specific message, if there is one.
	ChatID     int64  `json:"chat_id,omitempty"`
	MessageSeq int64  `json:"message_seq,omitempty"`
	Reason     string `json:"reason"`
	Detail     string `json:"detail,omitempty"`
}

// handleReport files an abuse report.
//
// Rate limited hard. A report queue is a denial-of-service target in two
// directions: flooding it hides real reports, and mass-reporting one account
// is itself a form of harassment. The unique index on (reporter, subject)
// while unresolved handles the second; the limiter handles the first.
func (s *Service) handleReport(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	var req reportRequest
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		return err
	}

	if req.SubjectID == 0 {
		return httpx.ErrBadRequest("subject_id is required")
	}
	if req.SubjectID == claims.UserID {
		return httpx.ErrBadRequest("you cannot report yourself")
	}

	reason := pgstore.ReportReason(strings.TrimSpace(req.Reason))
	if !pgstore.ValidReportReason(reason) {
		return httpx.ErrBadRequest(
			"reason must be one of spam, abuse, violence, csam, illegal, impersonation, other")
	}
	if len([]rune(req.Detail)) > 2000 {
		return httpx.ErrBadRequest("detail must be at most 2000 characters")
	}

	if err := s.checkLimit(r.Context(),
		ratelimit.KeyUser("report", claims.UserID), ratelimit.FileReport); err != nil {
		return err
	}

	if _, err := s.Users.GetByID(r.Context(), req.SubjectID); err != nil {
		return httpx.ErrNotFound("no such user")
	}

	rep := pgstore.Report{
		ID:         s.IDs.Next(),
		ReporterID: claims.UserID,
		SubjectID:  req.SubjectID,
		Reason:     reason,
		Detail:     req.Detail,
	}

	// A message reference is only accepted if the reporter can actually see
	// the message. Otherwise the report endpoint becomes an oracle for whether
	// an arbitrary (chat, seq) pair exists.
	if req.ChatID != 0 {
		if _, err := s.requireMember(r.Context(), req.ChatID, claims.UserID); err != nil {
			return httpx.ErrBadRequest("you can only report a message in a chat you are in")
		}
		rep.ChatID = &req.ChatID
		if req.MessageSeq > 0 {
			rep.MessageSeq = &req.MessageSeq
		}
	}

	created, err := s.Reports.Create(r.Context(), rep)
	if err != nil {
		if errors.Is(err, pgstore.ErrDuplicateReport) {
			// Not an error from the user's point of view: their earlier report
			// is still in the queue and a second one adds nothing.
			httpx.WriteJSON(w, http.StatusOK, map[string]any{
				"filed":   true,
				"pending": true,
				"message": "you have already reported this account; it is still being reviewed",
			})
			return nil
		}
		return httpx.ErrInternal("could not file the report").WithCause(err)
	}

	// Reports are not audited through auditlog. They are user actions, not
	// administrative ones, and there are far too many of them — the audit
	// trail records what *staff* did in response, which is the part that needs
	// to be accountable. The reports table is itself the record of the rest.
	s.Log.Info("report filed",
		"report_id", created.ID,
		"reason", created.Reason,
		"urgent", created.Reason.IsUrgent())

	if created.Reason.IsUrgent() {
		// CSAM and credible violence carry legal reporting obligations with
		// clocks attached. Surfacing them at warn level puts them in the alert
		// path rather than only in a queue somebody reads on Monday.
		s.Log.Warn("URGENT report requires prompt review",
			"report_id", created.ID,
			"reason", created.Reason,
			"subject_id", created.SubjectID,
			"chat_id", strconv.FormatInt(req.ChatID, 10))
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"filed":     true,
		"report_id": strconv.FormatInt(created.ID, 10),
	})
	return nil
}
