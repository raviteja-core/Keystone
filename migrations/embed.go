package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed auth/*.sql authz/*.sql
var EmbedFS embed.FS

// Run applies all pending database migrations for the target service (auth or authz).
func Run(ctx context.Context, logger *slog.Logger, dbURL, service string) error {
	if service != "auth" && service != "authz" {
		return fmt.Errorf("invalid service for migration: %q, must be 'auth' or 'authz'", service)
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return fmt.Errorf("failed to open database connection for migrations: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	goose.SetBaseFS(EmbedFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	logger.Info("running database migrations", slog.String("service", service), slog.String("dir", service))
	if err := goose.UpContext(ctx, db, service); err != nil {
		return fmt.Errorf("migration failed for service %s: %w", service, err)
	}

	logger.Info("database migrations completed successfully", slog.String("service", service))
	return nil
}
