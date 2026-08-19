// Package pgstore owns the Cloud SQL for PostgreSQL access layer: accounts,
// devices, chats, membership and contacts.
//
// The split with Cassandra is deliberate. Postgres holds the small,
// relational, mutable data that benefits from joins, foreign keys and
// transactions — a few hundred bytes per user that changes rarely. Cassandra
// holds the unbounded, append-only message history. Putting membership in
// Cassandra would make "add a member" a read-modify-write race; putting
// messages in Postgres would make the write rate the platform's ceiling.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("pgstore: not found")

// ErrConflict is returned on a unique-constraint violation.
var ErrConflict = errors.New("pgstore: conflict")

// Config describes the Cloud SQL connection.
type Config struct {
	// DSN is a libpq connection string. In GKE it points at the Cloud SQL
	// Auth Proxy sidecar on 127.0.0.1:5432, which handles IAM authentication
	// and TLS, so the DSN itself carries no password when IAM auth is used.
	DSN string
	// MaxConns must be sized against the Cloud SQL instance's connection
	// limit divided by the number of pods, not per pod in isolation: 50 pods
	// at 20 connections each will exhaust a db-custom-4-16384 instance.
	MaxConns int32
	MinConns int32

	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	ConnectTimeout  time.Duration
	// StatementTimeout is enforced by the server so a runaway query cannot
	// hold a connection for the full request timeout.
	StatementTimeout time.Duration
}

// DefaultConfig returns production-shaped defaults.
func DefaultConfig() Config {
	return Config{
		MaxConns:         20,
		MinConns:         2,
		MaxConnLifetime:  30 * time.Minute,
		MaxConnIdleTime:  5 * time.Minute,
		ConnectTimeout:   5 * time.Second,
		StatementTimeout: 10 * time.Second,
	}
}

// DB is the connection pool.
type DB struct{ pool *pgxpool.Pool }

// Connect opens the pool and verifies connectivity.
func Connect(ctx context.Context, cfg Config) (*DB, error) {
	if cfg.DSN == "" {
		return nil, errors.New("pgstore: DSN is empty")
	}
	pc, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("pgstore: parse DSN: %w", err)
	}

	pc.MaxConns = cfg.MaxConns
	pc.MinConns = cfg.MinConns
	pc.MaxConnLifetime = cfg.MaxConnLifetime
	pc.MaxConnIdleTime = cfg.MaxConnIdleTime
	pc.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	if cfg.StatementTimeout > 0 {
		pc.ConnConfig.RuntimeParams["statement_timeout"] =
			fmt.Sprintf("%d", cfg.StatementTimeout.Milliseconds())
		// Never let a client sit inside an open transaction; an abandoned one
		// blocks vacuum and eventually bloats the table.
		pc.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "30000"
	}
	pc.ConnConfig.RuntimeParams["application_name"] = "messaging"

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("pgstore: create pool: %w", err)
	}

	db := &DB{pool: pool}
	if err := db.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return db, nil
}

// Ping verifies the pool; used as a readiness check.
func (d *DB) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := d.pool.Ping(ctx); err != nil {
		return fmt.Errorf("pgstore: ping: %w", err)
	}
	return nil
}

// Pool exposes the pool for queries this package does not wrap.
func (d *DB) Pool() *pgxpool.Pool { return d.pool }

// Close drains the pool.
func (d *DB) Close(context.Context) error { d.pool.Close(); return nil }

// InTx runs fn inside a transaction, committing on nil and rolling back on
// error or panic.
func (d *DB) InTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("pgstore: begin: %w", err)
	}
	defer func() {
		// Rollback on an already-committed transaction is a no-op, so this is
		// safe on the happy path too.
		_ = tx.Rollback(context.WithoutCancel(ctx))
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pgstore: commit: %w", err)
	}
	return nil
}

// mapError converts driver errors into the package's sentinel errors.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
		case "23503": // foreign_key_violation
			return fmt.Errorf("pgstore: referenced row missing: %s", pgErr.ConstraintName)
		case "23514": // check_violation
			return fmt.Errorf("pgstore: check failed: %s", pgErr.ConstraintName)
		}
	}
	return err
}
