package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/platform/config"
	"github.com/raviteja-core/keystone/internal/platform/db"
	"github.com/raviteja-core/keystone/internal/platform/httpx"
	"github.com/raviteja-core/keystone/internal/platform/logging"
	"github.com/raviteja-core/keystone/migrations"
)

func main() {
	healthcheckFlag := flag.Bool("healthcheck", false, "Perform local readiness probe and exit 0 (healthy) or 1 (unhealthy)")
	flag.Parse()

	if *healthcheckFlag {
		adminAddr := os.Getenv("KEYSTONE_ADMIN_ADDR")
		if adminAddr == "" {
			adminAddr = ":9101"
		}
		if err := runHealthcheck(adminAddr); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	logger := logging.NewJSONLogger(os.Stdout, slog.LevelInfo)
	logger.Info("starting keystone authz engine", slog.String("version", "0.1.0"))

	cfg, err := config.LoadFromEnv(":8081", ":9101")
	if err != nil {
		logger.Error("configuration validation failed", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "FATAL: configuration error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Initialize database connection pool
	pool, err := db.NewPool(ctx, db.DefaultConfig(cfg.DatabaseURL))
	if err != nil {
		logger.Error("failed to connect to authz database", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "FATAL: database connection error: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Run embedded database migrations
	if err := migrations.Run(ctx, logger, cfg.DatabaseURL, "authz"); err != nil {
		logger.Error("database migration failed", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "FATAL: migration error: %v\n", err)
		os.Exit(1)
	}

	// Public HTTP router
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "keystone-authz",
			"version": "0.1.0",
		})
	})

	// Wrap public handler in middleware stack
	publicHandler := httpx.RequestID(
		httpx.Recover(logger)(
			httpx.AccessLog(logger)(
				httpx.SecurityHeaders(
					httpx.MaxBodyBytes(65536)(publicMux),
				),
			),
		),
	)

	// Admin HTTP router (healthz, readyz, metrics)
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /healthz", handleHealthz)
	adminMux.HandleFunc("GET /readyz", handleReadyz(pool))

	adminHandler := httpx.RequestID(
		httpx.Recover(logger)(
			adminMux,
		),
	)

	publicServer := httpx.NewServer(httpx.DefaultServerConfig(cfg.HTTPAddr, publicHandler))
	adminServer := httpx.NewServer(httpx.DefaultServerConfig(cfg.AdminAddr, adminHandler))

	if err := httpx.RunWithGracefulShutdown(logger, 10*time.Second, publicServer, adminServer); err != nil {
		logger.Error("server encountered fatal runtime error", slog.Any("error", err))
		os.Exit(1)
	}
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleReadyz(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := pool.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "unavailable",
				"error":  err.Error(),
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}
}

func runHealthcheck(addr string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("http://localhost%s/readyz", addr)
	if addr[0] != ':' {
		url = fmt.Sprintf("http://%s/readyz", addr)
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness probe returned status %d", resp.StatusCode)
	}
	return nil
}
