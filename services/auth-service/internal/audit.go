package auth

import (
	"context"
	"net/http"

	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/httpx"
)

// audit records an account-lifecycle action.
//
// Same shape and same reasoning as the chat service's: written after the
// action succeeds so the trail never claims something that did not happen, and
// a write failure is logged rather than failed back to the caller — the
// account really was deleted, and telling the client to retry would be wrong.
//
// What is deliberately *not* recorded here is the sign-in path. Successful
// logins are ordinary, they happen constantly, and adding them would drown the
// administrative entries. Failed logins are rate-limiter and alerting
// territory, not audit-trail territory.
func (s *Service) audit(ctx context.Context, r *http.Request, e auditlog.Entry) {
	if s.Audit == nil {
		return
	}

	e.ActorIP = httpx.ClientIP(r)
	if e.ActorType == "" {
		e.ActorType = "user"
	}

	if err := s.Audit.Record(ctx, e); err != nil {
		s.Log.Error("could not write an audit entry — this action is not in the audit trail",
			"action", e.Action,
			"actor_id", e.ActorID,
			"target_type", e.TargetType,
			"target_id", e.TargetID,
			"error", err)
	}
}
