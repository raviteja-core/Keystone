package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Advisory lock ID for audit hash chain serialization (ASCII "KEY_AUDI").
const AuditChainLockID = int64(0x4b45595f41554449)

// Standard Event Actions per §6.14
const (
	ActionUserRegistered     = "user.registered"
	ActionAuthLoginSucceeded = "auth.login_succeeded"
	ActionAuthLoginFailed    = "auth.login_failed"
	ActionSessionCreated     = "session.created"
	ActionTokenIssued        = "token.issued"
	ActionRefreshTokenReuse  = "refresh_token.reuse_detected"
	ActionAuthCodeReuse      = "auth_code.reuse_detected"
	ActionClientCreated      = "client.created"
)

// Outcome values
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// Event represents an audit event to be recorded.
type Event struct {
	ActorType  string         `json:"actor_type"`
	ActorID    *string        `json:"actor_id,omitempty"`
	Action     string         `json:"action"`
	TargetType *string        `json:"target_type,omitempty"`
	TargetID   *string        `json:"target_id,omitempty"`
	Outcome    string         `json:"outcome"`
	IP         *string        `json:"ip,omitempty"`
	UserAgent  *string        `json:"user_agent,omitempty"`
	RequestID  *string        `json:"request_id,omitempty"`
	Metadata   map[string]any `json:"metadata"`
}

// Record represents a persisted audit event with its hash chain link.
type Record struct {
	ID        int64           `json:"id"`
	TS        time.Time       `json:"ts"`
	ActorType string          `json:"actor_type"`
	ActorID   *string         `json:"actor_id,omitempty"`
	Action    string          `json:"action"`
	Outcome   string          `json:"outcome"`
	Metadata  json.RawMessage `json:"metadata"`
	PrevHash  []byte          `json:"prev_hash"`
	Hash      []byte          `json:"hash"`
}

// CanonicalEvent is the exact normalized payload hashed for the chain.
type CanonicalEvent struct {
	TS         string          `json:"ts"`
	ActorType  string          `json:"actor_type"`
	ActorID    *string         `json:"actor_id,omitempty"`
	Action     string          `json:"action"`
	TargetType *string         `json:"target_type,omitempty"`
	TargetID   *string         `json:"target_id,omitempty"`
	Outcome    string          `json:"outcome"`
	IP         *string         `json:"ip,omitempty"`
	UserAgent  *string         `json:"user_agent,omitempty"`
	RequestID  *string         `json:"request_id,omitempty"`
	Metadata   json.RawMessage `json:"metadata"`
}

// Writer appends audit events with a cryptographic SHA-256 hash chain.
type Writer struct {
	pool *pgxpool.Pool
}

// NewWriter creates a new audit Writer.
func NewWriter(pool *pgxpool.Pool) *Writer {
	return &Writer{pool: pool}
}

// Record inserts an audit event holding a transaction-level advisory lock to serialize the hash chain.
func (w *Writer) Record(ctx context.Context, e Event) (*Record, error) {
	if w.pool == nil {
		return nil, errors.New("audit writer pool is nil")
	}

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin audit transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// 1. Acquire transaction advisory lock to serialize chain computation across all nodes
	_, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", AuditChainLockID)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire audit advisory lock: %w", err)
	}

	// 2. Fetch the latest record's hash to link against
	var prevHash []byte
	err = tx.QueryRow(ctx, "SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&prevHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Genesis block: 32 zero bytes
			prevHash = make([]byte, 32)
		} else {
			return nil, fmt.Errorf("failed to query last audit hash: %w", err)
		}
	}

	now := time.Now().UTC()
	metaJSON, err := json.Marshal(e.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	// Clean IP address
	var ipStr *string
	if e.IP != nil && *e.IP != "" {
		host := *e.IP
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ipStr = &host
	}

	// 3. Compute Canonical JSON for the event
	canonical := CanonicalEvent{
		TS:         now.Format(time.RFC3339Nano),
		ActorType:  e.ActorType,
		ActorID:    e.ActorID,
		Action:     e.Action,
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Outcome:    e.Outcome,
		IP:         ipStr,
		UserAgent:  e.UserAgent,
		RequestID:  e.RequestID,
		Metadata:   metaJSON,
	}

	canonicalBytes, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize canonical audit event: %w", err)
	}

	// 4. hash = SHA256(prev_hash || canonical_bytes)
	h := sha256.New()
	h.Write(prevHash)
	h.Write(canonicalBytes)
	eventHash := h.Sum(nil)

	// 5. Insert into audit_events
	var id int64
	var insertedTS time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO audit_events (
			ts, actor_type, actor_id, action, target_type, target_id, outcome,
			ip, user_agent, request_id, metadata, prev_hash, hash
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13
		) RETURNING id, ts
	`, now, e.ActorType, e.ActorID, e.Action, e.TargetType, e.TargetID, e.Outcome,
		ipStr, e.UserAgent, e.RequestID, metaJSON, prevHash, eventHash).Scan(&id, &insertedTS)
	if err != nil {
		return nil, fmt.Errorf("failed to insert audit event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit audit event: %w", err)
	}

	return &Record{
		ID:        id,
		TS:        insertedTS,
		ActorType: e.ActorType,
		ActorID:   e.ActorID,
		Action:    e.Action,
		Outcome:   e.Outcome,
		Metadata:  metaJSON,
		PrevHash:  prevHash,
		Hash:      eventHash,
	}, nil
}
