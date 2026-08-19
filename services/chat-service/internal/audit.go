package chat

import (
	"context"
	"net/http"

	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/httpx"
)

// Audit recording for administrative actions.
//
// Ordering: entries are written *after* the action succeeds, so the log never
// claims something happened that did not. The cost is a window — a pod killed
// between the Postgres commit and the Kafka publish loses that one entry.
// The alternative, recording first, trades a missing entry for a false one,
// and a log that reports removals which never occurred is worse than one with
// a known gap: the gap is detectable from the sequence numbers, the lie is not.
//
// Failure handling: a failed audit write does not fail the request. The member
// really was removed; returning an error would tell the caller to retry an
// action that already took effect. It is logged at error level and counted, so
// the gap is visible in monitoring rather than silent.

// audit records an administrative action, attributing it to the caller.
//
// The entry carries no message content and no personal data beyond the
// identifiers already present in the request path — see the note on
// auditlog.Entry.Detail for why.
func (s *Service) audit(ctx context.Context, r *http.Request, e auditlog.Entry) {
	if s.Audit == nil {
		// Unset in tests and in single-purpose builds. A nil logger must not
		// panic on a path that is otherwise working.
		return
	}

	e.ActorIP = httpx.ClientIP(r)
	if e.ActorType == "" {
		e.ActorType = "user"
	}

	if err := s.Audit.Record(ctx, e); err != nil {
		s.Log.Error("could not write an audit entry — this administrative action is not in the audit trail",
			"action", e.Action,
			"actor_id", e.ActorID,
			"target_type", e.TargetType,
			"target_id", e.TargetID,
			"error", err)
	}
}
