package chat

import (
	"net/http"
	"testing"

	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
)

// Exhaustive tables rather than a few examples. These rules decide whether a
// chat can be taken over, and the interesting cases — admin against admin,
// anyone against the owner, an actor acting on themselves — are precisely the
// ones a happy-path test never reaches.

func member(id int64, role pgstore.MemberRole) pgstore.Member {
	return pgstore.Member{UserID: id, Role: role}
}

// status extracts the HTTP status an error would produce, or 200 for nil.
func status(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if apiErr, ok := err.(*httpx.APIError); ok {
		return apiErr.Status()
	}
	return http.StatusInternalServerError
}

const (
	allow  = http.StatusOK
	denied = http.StatusForbidden
	bad    = http.StatusBadRequest
)

func TestCanRemoveMember(t *testing.T) {
	roles := []pgstore.MemberRole{
		pgstore.RoleOwner, pgstore.RoleAdmin, pgstore.RoleMember, pgstore.RoleRestricted,
	}

	// want[actor][target]. Every combination is stated, so adding a role
	// without deciding its rules fails the completeness check below.
	want := map[pgstore.MemberRole]map[pgstore.MemberRole]int{
		pgstore.RoleOwner: {
			pgstore.RoleOwner:      denied, // nobody removes the owner, not even the owner
			pgstore.RoleAdmin:      allow,
			pgstore.RoleMember:     allow,
			pgstore.RoleRestricted: allow,
		},
		pgstore.RoleAdmin: {
			pgstore.RoleOwner:      denied,
			pgstore.RoleAdmin:      denied, // the escalation guard
			pgstore.RoleMember:     allow,
			pgstore.RoleRestricted: allow,
		},
		pgstore.RoleMember: {
			pgstore.RoleOwner:      denied,
			pgstore.RoleAdmin:      denied,
			pgstore.RoleMember:     denied,
			pgstore.RoleRestricted: denied,
		},
		pgstore.RoleRestricted: {
			pgstore.RoleOwner:      denied,
			pgstore.RoleAdmin:      denied,
			pgstore.RoleMember:     denied,
			pgstore.RoleRestricted: denied,
		},
	}

	for _, actorRole := range roles {
		for _, targetRole := range roles {
			got := status(canRemoveMember(member(1, actorRole), member(2, targetRole)))
			if got != want[actorRole][targetRole] {
				t.Errorf("%s removing %s: status %d, want %d",
					actorRole, targetRole, got, want[actorRole][targetRole])
			}
		}
	}
}

func TestAnAdminCannotRemoveAFellowAdmin(t *testing.T) {
	// Called out separately because it is the rule most likely to be "fixed"
	// by someone who thinks it is an oversight. It is not: without it, one
	// compromised admin account removes the other admins and takes the chat.
	if err := canRemoveMember(member(1, pgstore.RoleAdmin), member(2, pgstore.RoleAdmin)); err == nil {
		t.Fatal("an admin was allowed to remove a fellow admin — one compromised admin account now takes the chat")
	}
	// The owner may, which is what keeps the chat administrable.
	if err := canRemoveMember(member(1, pgstore.RoleOwner), member(2, pgstore.RoleAdmin)); err != nil {
		t.Fatalf("the owner could not remove an admin: %v", err)
	}
}

func TestCanSetRole(t *testing.T) {
	roles := []pgstore.MemberRole{
		pgstore.RoleOwner, pgstore.RoleAdmin, pgstore.RoleMember, pgstore.RoleRestricted,
	}

	cases := []struct {
		actor, target pgstore.MemberRole
		to            pgstore.MemberRole
		want          int
		why           string
	}{
		// The owner may do anything except touch the owner role.
		{pgstore.RoleOwner, pgstore.RoleMember, pgstore.RoleAdmin, allow, "owner promotes a member"},
		{pgstore.RoleOwner, pgstore.RoleAdmin, pgstore.RoleMember, allow, "owner demotes an admin"},
		{pgstore.RoleOwner, pgstore.RoleMember, pgstore.RoleRestricted, allow, "owner restricts a member"},
		{pgstore.RoleOwner, pgstore.RoleRestricted, pgstore.RoleMember, allow, "owner unrestricts"},

		// Admins may moderate ordinary members but not create or unmake admins.
		{pgstore.RoleAdmin, pgstore.RoleMember, pgstore.RoleRestricted, allow, "admin restricts a member"},
		{pgstore.RoleAdmin, pgstore.RoleRestricted, pgstore.RoleMember, allow, "admin unrestricts"},
		{pgstore.RoleAdmin, pgstore.RoleMember, pgstore.RoleAdmin, denied, "admin tries to create an admin"},
		{pgstore.RoleAdmin, pgstore.RoleAdmin, pgstore.RoleMember, denied, "admin tries to demote an admin"},
		{pgstore.RoleAdmin, pgstore.RoleAdmin, pgstore.RoleRestricted, denied, "admin tries to restrict an admin"},

		// Ordinary members may change nobody.
		{pgstore.RoleMember, pgstore.RoleMember, pgstore.RoleAdmin, denied, "member promotes"},
		{pgstore.RoleMember, pgstore.RoleMember, pgstore.RoleRestricted, denied, "member restricts"},
		{pgstore.RoleRestricted, pgstore.RoleMember, pgstore.RoleMember, denied, "restricted member acts"},

		// The owner's role is immutable from every direction.
		{pgstore.RoleOwner, pgstore.RoleOwner, pgstore.RoleMember, denied, "owner demotes the owner"},
		{pgstore.RoleAdmin, pgstore.RoleOwner, pgstore.RoleMember, denied, "admin demotes the owner"},
		{pgstore.RoleMember, pgstore.RoleOwner, pgstore.RoleMember, denied, "member demotes the owner"},

		// Ownership is not granted here.
		{pgstore.RoleOwner, pgstore.RoleMember, pgstore.RoleOwner, bad, "owner grants ownership"},
		{pgstore.RoleAdmin, pgstore.RoleMember, pgstore.RoleOwner, bad, "admin grants ownership"},
	}

	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			// Distinct ids, so the self-check does not interfere.
			got := status(canSetRole(member(1, tc.actor), member(2, tc.target), tc.to))
			if got != tc.want {
				t.Errorf("status %d, want %d", got, tc.want)
			}
		})
	}

	// Nobody, of any role, may change their own.
	for _, role := range roles {
		for _, to := range roles {
			if to == pgstore.RoleOwner {
				continue // covered by the ownership case above
			}
			err := canSetRole(member(1, role), member(1, role), to)
			if status(err) != denied {
				t.Errorf("a %s changed their own role to %s (status %d)", role, to, status(err))
			}
		}
	}
}

func TestSetRoleRejectsAnUnknownRole(t *testing.T) {
	// An unrecognised value must be a 400 naming the field, not a silent
	// write of a role no code understands.
	for _, bogus := range []pgstore.MemberRole{"", "superuser", "OWNER", "admin ", "root"} {
		err := canSetRole(member(1, pgstore.RoleOwner), member(2, pgstore.RoleMember), bogus)
		if status(err) != bad {
			t.Errorf("canSetRole(_, _, %q) → status %d, want 400", bogus, status(err))
		}
	}
}

func TestSetRoleValidatesBeforeCheckingPrivilege(t *testing.T) {
	// A member sending a bogus role should learn the role is invalid, not that
	// they lack privilege — otherwise a typo looks like a permissions problem
	// and gets escalated to support.
	err := canSetRole(member(1, pgstore.RoleMember), member(2, pgstore.RoleMember), "nonsense")
	if status(err) != bad {
		t.Errorf("status %d, want 400 — validation should precede the privilege check", status(err))
	}
}

func TestCanDeleteChat(t *testing.T) {
	cases := []struct {
		actor pgstore.MemberRole
		kind  pgstore.ChatType
		want  int
		why   string
	}{
		{pgstore.RoleOwner, pgstore.ChatGroup, allow, "owner deletes a group"},
		{pgstore.RoleOwner, pgstore.ChatChannel, allow, "owner deletes a channel"},
		{pgstore.RoleAdmin, pgstore.ChatGroup, denied, "admin cannot delete a group"},
		{pgstore.RoleMember, pgstore.ChatGroup, denied, "member cannot delete a group"},

		// A private chat belongs to both participants equally, so neither may
		// destroy the other's copy. Note the owner case is a 400, not a 403:
		// the operation is wrong for the chat type, not a privilege problem.
		{pgstore.RoleOwner, pgstore.ChatPrivate, bad, "owner cannot delete a private chat"},
		{pgstore.RoleMember, pgstore.ChatPrivate, bad, "member cannot delete a private chat"},
	}

	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			got := status(canDeleteChat(member(1, tc.actor), pgstore.Chat{Type: tc.kind}))
			if got != tc.want {
				t.Errorf("status %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCanDeleteMessage(t *testing.T) {
	const me, someoneElse = int64(1), int64(2)

	cases := []struct {
		role           pgstore.MemberRole
		sender         int64
		wantStatus     int
		wantModeration bool
		why            string
	}{
		{pgstore.RoleMember, me, allow, false, "member deletes their own"},
		{pgstore.RoleRestricted, me, allow, false, "restricted member deletes their own"},
		{pgstore.RoleOwner, me, allow, false, "owner deletes their own"},

		{pgstore.RoleMember, someoneElse, denied, false, "member deletes another's"},
		{pgstore.RoleRestricted, someoneElse, denied, false, "restricted deletes another's"},

		{pgstore.RoleAdmin, someoneElse, allow, true, "admin moderates"},
		{pgstore.RoleOwner, someoneElse, allow, true, "owner moderates"},
	}

	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			moderation, err := canDeleteMessage(member(me, tc.role), tc.sender)
			if status(err) != tc.wantStatus {
				t.Errorf("status %d, want %d", status(err), tc.wantStatus)
			}
			if moderation != tc.wantModeration {
				t.Errorf("moderation = %v, want %v — this decides whether it is audited",
					moderation, tc.wantModeration)
			}
		})
	}
}

func TestDeletingYourOwnMessageIsNeverAudited(t *testing.T) {
	// Auditing every self-delete would bury the handful of moderation entries
	// under millions of ordinary ones, which is the same as not having them.
	for _, role := range []pgstore.MemberRole{
		pgstore.RoleOwner, pgstore.RoleAdmin, pgstore.RoleMember, pgstore.RoleRestricted,
	} {
		moderation, err := canDeleteMessage(member(1, role), 1)
		if err != nil {
			t.Errorf("%s could not delete their own message: %v", role, err)
		}
		if moderation {
			t.Errorf("%s deleting their own message was recorded as moderation", role)
		}
	}
}
