package migrations_test

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/raviteja-core/keystone/migrations"
)

func getDBURL() string {
	url := os.Getenv("KEYSTONE_DATABASE_URL")
	if url == "" {
		port := os.Getenv("KEYSTONE_POSTGRES_PORT")
		if port == "" {
			port = "54320"
		}
		url = "postgres://keystone_auth_app:auth_dev_password@localhost:" + port + "/keystone_auth?sslmode=disable"
	}
	return url
}

func TestMigrations_Auth_IdempotentAndTriggers(t *testing.T) {
	dbURL := getDBURL()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Probe AS-32: Running migrations twice must succeed cleanly
	if err := migrations.Run(ctx, logger, dbURL, "auth"); err != nil {
		t.Skipf("skipping migration test: postgres not reachable: %v", err)
	}

	if err := migrations.Run(ctx, logger, dbURL, "auth"); err != nil {
		t.Fatalf("AS-32: running migrations second time failed: %v", err)
	}

	// Verify audit_events append-only trigger
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Insert a dummy event
	var eventID int64
	zeroHash := make([]byte, 32)
	err = db.QueryRowContext(ctx, `
		INSERT INTO audit_events (
			actor_type, actor_id, action, target_type, target_id, outcome, metadata, prev_hash, hash
		) VALUES (
			'system', 'init', 'test.event', 'test', '1', 'success', '{}'::jsonb, $1, $1
		) RETURNING id
	`, zeroHash).Scan(&eventID)
	if err != nil {
		t.Fatalf("failed to insert audit event: %v", err)
	}

	// Attempt UPDATE -> MUST FAIL via trigger
	_, updateErr := db.ExecContext(ctx, "UPDATE audit_events SET action = 'tampered' WHERE id = $1", eventID)
	if updateErr == nil {
		t.Fatalf("CRITICAL SECURITY VIOLATION: UPDATE on audit_events succeeded; append-only trigger failed")
	}

	// Attempt DELETE -> MUST FAIL via trigger
	_, deleteErr := db.ExecContext(ctx, "DELETE FROM audit_events WHERE id = $1", eventID)
	if deleteErr == nil {
		t.Fatalf("CRITICAL SECURITY VIOLATION: DELETE on audit_events succeeded; append-only trigger failed")
	}
}

func getAuthzDBURL() string {
	url := os.Getenv("KEYSTONE_AUTHZ_DB_URL")
	if url == "" {
		port := os.Getenv("KEYSTONE_POSTGRES_PORT")
		if port == "" {
			port = "54320"
		}
		url = "postgres://keystone_authz_app:authz_dev_password@localhost:" + port + "/keystone_authz?sslmode=disable"
	}
	return url
}

func TestMigrations_Authz_Idempotent(t *testing.T) {
	dbURL := getAuthzDBURL()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := migrations.Run(ctx, logger, dbURL, "authz"); err != nil {
		t.Fatalf("running authz migrations failed: %v", err)
	}

	// Running second time must be idempotent
	if err := migrations.Run(ctx, logger, dbURL, "authz"); err != nil {
		t.Fatalf("running authz migrations second time failed: %v", err)
	}
}
