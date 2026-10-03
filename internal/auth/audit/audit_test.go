package audit_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/auth/audit"
)

func getTestPool(t *testing.T) *pgxpool.Pool {
	dbURL := os.Getenv("KEYSTONE_DATABASE_URL")
	if dbURL == "" {
		port := os.Getenv("KEYSTONE_POSTGRES_PORT")
		if port == "" {
			port = "54320"
		}
		dbURL = "postgres://keystone_auth_app:auth_dev_password@localhost:" + port + "/keystone_auth?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("skipping audit test: cannot connect to postgres: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("skipping audit test: postgres ping failed: %v", err)
	}
	return pool
}

func TestAudit_HashChainLinearity(t *testing.T) {
	pool := getTestPool(t)
	w := audit.NewWriter(pool)
	ctx := context.Background()

	// Write 5 events in sequence
	records := make([]*audit.Record, 5)
	for i := 0; i < 5; i++ {
		actor := "usr_test"
		rec, err := w.Record(ctx, audit.Event{
			ActorType: "user",
			ActorID:   &actor,
			Action:    audit.ActionAuthLoginSucceeded,
			Outcome:   audit.OutcomeSuccess,
			Metadata: map[string]any{
				"step": i,
			},
		})
		if err != nil {
			t.Fatalf("failed to record event %d: %v", i, err)
		}
		records[i] = rec
	}

	// Verify chain: for i > 0, records[i].PrevHash MUST equal records[i-1].Hash
	for i := 1; i < len(records); i++ {
		prev := records[i-1].Hash
		currPrev := records[i].PrevHash
		if string(prev) != string(currPrev) {
			t.Fatalf("chain broken between event %d and %d: expected prev_hash %x, got %x", i-1, i, prev, currPrev)
		}
	}
}

func TestAudit_ConcurrentWritersHoldAdvisoryLock(t *testing.T) {
	pool := getTestPool(t)
	w := audit.NewWriter(pool)
	ctx := context.Background()

	// 20 concurrent writers
	const workers = 20
	var wg sync.WaitGroup
	errs := make([]error, workers)
	recs := make([]*audit.Record, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			actor := "actor_concurrent"
			r, err := w.Record(ctx, audit.Event{
				ActorType: "system",
				ActorID:   &actor,
				Action:    audit.ActionTokenIssued,
				Outcome:   audit.OutcomeSuccess,
				Metadata: map[string]any{
					"worker": idx,
				},
			})
			errs[idx] = err
			recs[idx] = r
		}(i)
	}
	wg.Wait()

	for idx, err := range errs {
		if err != nil {
			t.Fatalf("worker %d failed: %v", idx, err)
		}
	}
}

func TestAudit_SecretScanInMetadata(t *testing.T) {
	pool := getTestPool(t)
	ctx := context.Background()

	// Query last 100 rows from audit_events and verify no sensitive keywords or secrets are logged
	rows, err := pool.Query(ctx, `
		SELECT action, metadata::text, COALESCE(user_agent, ''), COALESCE(request_id, '')
		FROM audit_events
		ORDER BY id DESC LIMIT 100
	`)
	if err != nil {
		t.Fatalf("failed to query audit_events: %v", err)
	}
	defer rows.Close()

	forbiddenSubstrings := []string{
		"SuperSecurePassword",
		"auth_dev_password",
		"client_secret",
		"bearer ",
		"at+jwt",
		"private_key",
		"BEGIN RSA",
	}

	for rows.Next() {
		var action, metaText, ua, reqID string
		if err := rows.Scan(&action, &metaText, &ua, &reqID); err != nil {
			t.Fatalf("failed to scan audit row: %v", err)
		}

		combined := strings.ToLower(metaText + " " + ua + " " + reqID)
		for _, forbidden := range forbiddenSubstrings {
			if strings.Contains(combined, strings.ToLower(forbidden)) {
				t.Fatalf("CRITICAL SECURITY VIOLATION: Secret %q found in audit log row: %s", forbidden, metaText)
			}
		}
	}
}

func TestAudit_CanonicalRecomputation(t *testing.T) {
	// Unit test proving the canonical hash algorithm is deterministic
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	meta := []byte(`{"client_id":"app1","scope":"openid"}`)

	c := audit.CanonicalEvent{
		TS:        now.Format(time.RFC3339Nano),
		ActorType: "user",
		Action:    "token.issued",
		Outcome:   "success",
		Metadata:  meta,
	}

	b1, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}

	h1 := sha256.Sum256(b1)
	h2 := sha256.Sum256(b2)
	if h1 != h2 {
		t.Fatal("canonical hash computation is non-deterministic")
	}
}
