package chat

import (
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
)

// Chat privilege rules.
//
// These are the decisions that stop a chat being taken over, and they are
// pure functions rather than inline handler code for one reason: reaching
// them through a handler requires Postgres, Cassandra, Redis and Kafka, so in
// practice they would never be tested exhaustively. The combinations that
// matter — admin against admin, anyone against the owner, an actor acting on
// themselves — are exactly the ones an integration test skips.
//
// The handlers keep doing the I/O; only the judgement lives here.

// canRemoveMember reports whether actor may remove target from a chat.
//
//   - Owners and admins may remove; ordinary members may not.
//   - Nobody may remove the owner. A chat with no owner has no one who can
//     appoint one, and it cannot be recovered through the API.
//   - An admin may not remove a fellow admin. Otherwise one compromised admin
//     account escalates to sole control by removing the others; requiring the
//     owner means the takeover needs the one account that cannot be removed.
func canRemoveMember(actor, target pgstore.Member) error {
	if actor.Role != pgstore.RoleOwner && actor.Role != pgstore.RoleAdmin {
		return httpx.ErrForbidden("only owners and admins can remove members")
	}
	if target.Role == pgstore.RoleOwner {
		return httpx.ErrForbidden("you cannot remove this member")
	}
	if target.Role == pgstore.RoleAdmin && actor.Role != pgstore.RoleOwner {
		return httpx.ErrForbidden("you cannot remove this member")
	}
	return nil
}

// canSetRole reports whether actor may change target's role to `to`.
//
// Stricter than "admins can administrate", deliberately:
//
//   - Only the owner may grant or revoke admin. An admin promoting another
//     admin is the same escalation canRemoveMember guards against, run
//     forwards instead of backwards.
//   - Nobody may change the owner's role, the owner included. Demoting the
//     owner leaves a chat that cannot appoint one.
//   - Nobody may set the owner role here. A chat has exactly one owner and
//     transfer must move it, not add a second.
//   - Nobody may change their own role. An admin who demotes themselves by
//     accident is unrecoverable without an owner.
//
// The self check comes before the others so "you cannot change your own role"
// is what an owner sees, rather than the more confusing message about the
// owner's role being immutable.
func canSetRole(actor, target pgstore.Member, to pgstore.MemberRole) error {
	switch to {
	case pgstore.RoleMember, pgstore.RoleAdmin, pgstore.RoleRestricted:
	case pgstore.RoleOwner:
		return httpx.ErrBadRequest("ownership cannot be granted here; transfer it explicitly")
	default:
		return httpx.ErrBadRequest("role must be member, admin or restricted")
	}

	if actor.UserID == target.UserID {
		return httpx.ErrForbidden("you cannot change your own role")
	}
	if actor.Role != pgstore.RoleOwner && actor.Role != pgstore.RoleAdmin {
		return httpx.ErrForbidden("only owners and admins can change roles")
	}
	if target.Role == pgstore.RoleOwner {
		return httpx.ErrForbidden("the owner's role cannot be changed")
	}
	// Granting or revoking admin is the owner's alone. An admin may still
	// restrict or unrestrict an ordinary member, which is the day-to-day
	// moderation the endpoint exists for.
	if actor.Role != pgstore.RoleOwner && (to == pgstore.RoleAdmin || target.Role == pgstore.RoleAdmin) {
		return httpx.ErrForbidden("only the owner can grant or revoke admin")
	}
	return nil
}

// canDeleteChat reports whether actor may delete the chat.
//
// Owner only, and never for a private chat: deleting one would destroy the
// other participant's copy of a conversation they equally own. Leaving is the
// right operation there, and archiving is right for "I do not want to see
// this".
func canDeleteChat(actor pgstore.Member, chat pgstore.Chat) error {
	if chat.Type == pgstore.ChatPrivate {
		return httpx.ErrBadRequest("a private chat cannot be deleted; leave or archive it instead")
	}
	if actor.Role != pgstore.RoleOwner {
		return httpx.ErrForbidden("only the owner can delete this chat")
	}
	return nil
}

// canDeleteMessage reports whether actor may delete a message they did not
// necessarily send.
//
// A member may delete their own; owners and admins may delete anyone's. The
// second returned value says whether this was a moderation action, which is
// what decides if it reaches the audit trail — auditing every self-delete
// would bury the handful of entries that matter under millions that do not.
func canDeleteMessage(actor pgstore.Member, senderID int64) (moderation bool, err error) {
	if senderID == actor.UserID {
		return false, nil
	}
	if actor.Role != pgstore.RoleOwner && actor.Role != pgstore.RoleAdmin {
		return false, httpx.ErrForbidden("you cannot delete this message")
	}
	return true, nil
}
