package pgstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Reports is the abuse-report repository.
type Reports struct{ db *DB }

// ReportsRepo returns the report repository.
func (d *DB) ReportsRepo() *Reports { return &Reports{db: d} }

// ReportReason is why something was reported.
type ReportReason string

const (
	ReasonSpam          ReportReason = "spam"
	ReasonAbuse         ReportReason = "abuse"
	ReasonViolence      ReportReason = "violence"
	ReasonCSAM          ReportReason = "csam"
	ReasonIllegal       ReportReason = "illegal"
	ReasonImpersonation ReportReason = "impersonation"
	ReasonOther         ReportReason = "other"
)

// ValidReportReason reports whether r is one the database will accept.
//
// Checked in Go as well as by the CHECK constraint so a bad value becomes a
// 400 naming the field, rather than a constraint violation surfacing as a 500.
func ValidReportReason(r ReportReason) bool {
	switch r {
	case ReasonSpam, ReasonAbuse, ReasonViolence, ReasonCSAM,
		ReasonIllegal, ReasonImpersonation, ReasonOther:
		return true
	}
	return false
}

// IsUrgent reports whether a reason demands review ahead of the queue.
//
// CSAM and credible violence are not "high priority" in the sense of sorting
// order — they carry legal reporting obligations with clocks attached, and a
// queue that treats them as ordinary spam will miss those deadlines.
func (r ReportReason) IsUrgent() bool {
	return r == ReasonCSAM || r == ReasonViolence
}

// ReportState is where a report is in review.
type ReportState string

const (
	StateOpen      ReportState = "open"
	StateReviewing ReportState = "reviewing"
	StateActioned  ReportState = "actioned"
	StateDismissed ReportState = "dismissed"
)

// Report is one abuse report.
type Report struct {
	ID         int64        `json:"id"`
	ReporterID int64        `json:"reporter_id"`
	SubjectID  int64        `json:"subject_id"`
	ChatID     *int64       `json:"chat_id,omitempty"`
	MessageSeq *int64       `json:"message_seq,omitempty"`
	Reason     ReportReason `json:"reason"`
	Detail     string       `json:"detail,omitempty"`
	State      ReportState  `json:"state"`
	ResolvedAt *time.Time   `json:"resolved_at,omitempty"`
	ResolvedBy string       `json:"resolved_by,omitempty"`
	Resolution string       `json:"resolution,omitempty"`
	CreatedAt  time.Time    `json:"created_at"`
}

const reportColumns = `id, reporter_id, subject_id, chat_id, message_seq,
	reason, detail, state, resolved_at, resolved_by, resolution, created_at`

func scanReport(row pgx.Row) (Report, error) {
	var r Report
	var resolvedBy, resolution *string
	err := row.Scan(&r.ID, &r.ReporterID, &r.SubjectID, &r.ChatID, &r.MessageSeq,
		&r.Reason, &r.Detail, &r.State, &r.ResolvedAt, &resolvedBy, &resolution, &r.CreatedAt)
	if err != nil {
		return Report{}, mapError(err)
	}
	if resolvedBy != nil {
		r.ResolvedBy = *resolvedBy
	}
	if resolution != nil {
		r.Resolution = *resolution
	}
	return r, nil
}

// ErrDuplicateReport means this reporter already has an unresolved report open
// against this subject.
//
// A distinct error rather than a generic conflict, because the right response
// differs: the caller should tell the user their earlier report is still being
// reviewed, not that something went wrong.
var ErrDuplicateReport = errors.New("pgstore: an open report already exists for this pair")

// Create files a report.
func (r *Reports) Create(ctx context.Context, rep Report) (Report, error) {
	if rep.ReporterID == rep.SubjectID {
		return Report{}, fmt.Errorf("pgstore: a user cannot report themselves")
	}
	if !ValidReportReason(rep.Reason) {
		return Report{}, fmt.Errorf("pgstore: %q is not a valid report reason", rep.Reason)
	}

	row := r.db.pool.QueryRow(ctx, `
		INSERT INTO reports (id, reporter_id, subject_id, chat_id, message_seq, reason, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+reportColumns,
		rep.ID, rep.ReporterID, rep.SubjectID, rep.ChatID, rep.MessageSeq,
		string(rep.Reason), strings.TrimSpace(rep.Detail))

	out, err := scanReport(row)
	if err != nil {
		// The partial unique index on (reporter_id, subject_id) is what makes
		// a repeat report a conflict rather than a second queue entry.
		if errors.Is(err, ErrConflict) {
			return Report{}, ErrDuplicateReport
		}
		return Report{}, err
	}
	return out, nil
}

// Queue returns reports awaiting review, oldest first.
//
// Oldest first rather than newest: a moderation queue read newest-first
// starves its tail, and the reports that sit longest are the ones most likely
// to become a complaint about inaction.
func (r *Reports) Queue(ctx context.Context, limit, offset int) ([]Report, error) {
	rows, err := r.db.pool.Query(ctx, `
		SELECT `+reportColumns+`
		FROM reports
		WHERE state IN ('open', 'reviewing')
		ORDER BY created_at
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Report
	for rows.Next() {
		rep, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, mapError(rows.Err())
}

// AboutSubject returns every report filed against one account.
//
// The query a moderator runs before deciding. Ten separate reports from ten
// unrelated people is a very different signal from ten from one person, and
// neither is visible from a single report.
func (r *Reports) AboutSubject(ctx context.Context, subjectID int64, limit int) ([]Report, error) {
	rows, err := r.db.pool.Query(ctx, `
		SELECT `+reportColumns+`
		FROM reports
		WHERE subject_id = $1
		ORDER BY created_at DESC
		LIMIT $2`, subjectID, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Report
	for rows.Next() {
		rep, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, mapError(rows.Err())
}

// Resolve closes a report.
func (r *Reports) Resolve(ctx context.Context, id int64, state ReportState, by, resolution string) (Report, error) {
	if state != StateActioned && state != StateDismissed {
		return Report{}, fmt.Errorf("pgstore: a report resolves to actioned or dismissed, not %q", state)
	}
	if strings.TrimSpace(by) == "" {
		// The CHECK constraint enforces this too; catching it here produces a
		// message that names the problem instead of a constraint code.
		return Report{}, fmt.Errorf("pgstore: resolving a report requires the operator's identity")
	}

	row := r.db.pool.QueryRow(ctx, `
		UPDATE reports
		SET state = $2, resolved_at = now(), resolved_by = $3, resolution = $4
		WHERE id = $1 AND state IN ('open', 'reviewing')
		RETURNING `+reportColumns,
		id, string(state), by, strings.TrimSpace(resolution))

	rep, err := scanReport(row)
	if errors.Is(err, ErrNotFound) {
		// Either it does not exist or it is already resolved. Both mean "there
		// is nothing here to act on", and distinguishing them would leak
		// whether an id exists.
		return Report{}, ErrNotFound
	}
	return rep, err
}

// CountOpenAbout returns how many unresolved reports name this account.
//
// Used to surface a pattern without loading the reports themselves — cheap
// enough to include in a user lookup.
func (r *Reports) CountOpenAbout(ctx context.Context, subjectID int64) (int, error) {
	var n int
	err := r.db.pool.QueryRow(ctx,
		`SELECT count(*) FROM reports WHERE subject_id = $1 AND state IN ('open','reviewing')`,
		subjectID).Scan(&n)
	return n, mapError(err)
}

// ---------------------------------------------------------------------------
// Bans
// ---------------------------------------------------------------------------

// Ban marks an account banned.
//
// Every argument is required. A ban with no operator and no reason is a ban
// nobody can review, appeal or reverse with confidence, and those are exactly
// the ones that turn into a public problem.
func (r *Users) Ban(ctx context.Context, userID int64, by, reason string) error {
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("pgstore: banning an account requires the operator's identity")
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("pgstore: banning an account requires a reason")
	}

	tag, err := r.db.pool.Exec(ctx, `
		UPDATE users
		SET banned = true, banned_at = now(), banned_reason = $2, banned_by = $3, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL`,
		userID, strings.TrimSpace(reason), strings.TrimSpace(by))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Unban lifts a ban.
//
// The reason and operator are cleared along with the flag, because the
// constraint requires them to agree — the record of the ban having happened
// lives in the audit trail, which is the thing that cannot be edited.
func (r *Users) Unban(ctx context.Context, userID int64) error {
	tag, err := r.db.pool.Exec(ctx, `
		UPDATE users
		SET banned = false, banned_at = NULL, banned_reason = NULL, banned_by = NULL, updated_at = now()
		WHERE id = $1 AND banned = true`, userID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// BanStatus is the ban state of an account.
type BanStatus struct {
	Banned bool
	At     *time.Time
	Reason string
}

// IsBanned reports whether an account is banned.
//
// Kept deliberately narrow — it selects only the ban columns — so the auth
// service can call it on a hot path without pulling a whole user row, and so
// its Postgres grant does not need to include the phone number.
func (r *Users) IsBanned(ctx context.Context, userID int64) (BanStatus, error) {
	var st BanStatus
	var reason *string
	err := r.db.pool.QueryRow(ctx,
		`SELECT banned, banned_at, banned_reason FROM users WHERE id = $1`, userID).
		Scan(&st.Banned, &st.At, &reason)
	if err != nil {
		return BanStatus{}, mapError(err)
	}
	if reason != nil {
		st.Reason = *reason
	}
	return st, nil
}

// ListBanned returns every banned account and its reason.
//
// Used only by the reconcile pass, which is why it is unpaginated: the ban
// list is small by nature — a platform where it is not has a much larger
// problem than this query.
func (r *Users) ListBanned(ctx context.Context) (map[int64]string, error) {
	rows, err := r.db.pool.Query(ctx,
		`SELECT id, coalesce(banned_reason, '') FROM users WHERE banned = true AND deleted_at IS NULL`)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := make(map[int64]string)
	for rows.Next() {
		var id int64
		var reason string
		if err := rows.Scan(&id, &reason); err != nil {
			return nil, mapError(err)
		}
		out[id] = reason
	}
	return out, mapError(rows.Err())
}
