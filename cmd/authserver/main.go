package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/auth/audit"
	"github.com/raviteja-core/keystone/internal/auth/discovery"
	"github.com/raviteja-core/keystone/internal/auth/keys"
	"github.com/raviteja-core/keystone/internal/auth/oauth"
	"github.com/raviteja-core/keystone/internal/auth/password"
	"github.com/raviteja-core/keystone/internal/auth/session"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/auth/token"
	"github.com/raviteja-core/keystone/internal/auth/ui"
	"github.com/raviteja-core/keystone/internal/auth/userinfo"
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
			adminAddr = ":9100"
		}
		if err := runHealthcheck(adminAddr); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	logger := logging.NewJSONLogger(os.Stdout, slog.LevelInfo)
	logger.Info("starting keystone authserver", slog.String("version", "0.1.0"))

	cfg, err := config.LoadFromEnv(":8080", ":9100")
	if err != nil {
		logger.Error("configuration validation failed", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "FATAL: configuration error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Initialize database connection pool
	pool, err := db.NewPool(ctx, db.DefaultConfig(cfg.DatabaseURL))
	if err != nil {
		logger.Error("failed to connect to auth database", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "FATAL: database connection error: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Run embedded database migrations
	if err := migrations.Run(ctx, logger, cfg.DatabaseURL, "auth"); err != nil {
		logger.Error("database migration failed", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "FATAL: migration error: %v\n", err)
		os.Exit(1)
	}

	// Initialize persistence store
	authStore := store.New(pool)

	// Initialize signing key manager
	keyMgr, err := keys.NewManager(pool, cfg.MasterKey)
	if err != nil {
		logger.Error("failed to initialize key manager", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "FATAL: key manager error: %v\n", err)
		os.Exit(1)
	}

	// Ensure active signing key exists
	if _, err := keyMgr.EnsureActiveKey(ctx); err != nil {
		logger.Error("failed to ensure active signing key", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "FATAL: active key generation error: %v\n", err)
		os.Exit(1)
	}

	// Initialize password hasher
	hasher, err := password.NewHasher(password.Config{
		MemoryKiB:     cfg.Argon2MemoryKiB,
		Iterations:    cfg.Argon2Time,
		Parallelism:   cfg.Argon2Parallelism,
		MaxConcurrent: cfg.Argon2MaxConcurrent,
	})
	if err != nil {
		logger.Error("failed to initialize password hasher", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "FATAL: hasher initialization error: %v\n", err)
		os.Exit(1)
	}

	// Initialize session manager
	sessMgr := session.NewManager(authStore, session.Config{
		CookieSecure: cfg.CookieSecure,
		IdleTTL:      cfg.SessionIdleTTL,
		AbsoluteTTL:  cfg.SessionAbsoluteTTL,
	})

	// Initialize token validator for /userinfo
	tokenValidator := token.NewValidator(cfg.Issuer, "", func(kid string) (*rsa.PublicKey, error) {
		k, err := keyMgr.GetActiveKey(ctx)
		if err != nil || k == nil {
			return nil, errors.New("no active signing key")
		}
		if k.KID != kid {
			return nil, fmt.Errorf("signing key %q not found", kid)
		}
		return k.PublicKey, nil
	})

	// Public HTTP router
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "keystone-authserver",
			"version": "0.1.0",
			"issuer":  cfg.Issuer,
		})
	})

	// Discovery and JWKS
	publicMux.HandleFunc("GET /.well-known/openid-configuration", discovery.Handler(cfg.Issuer))
	publicMux.HandleFunc("GET /.well-known/oauth-authorization-server", discovery.Handler(cfg.Issuer))
	publicMux.HandleFunc("GET /jwks.json", keyMgr.Handler())

	// OAuth & OIDC endpoints
	authorizeHandler := oauth.NewAuthorizeHandler(cfg.Issuer, authStore, sessMgr, cfg.AuthCodeTTL, logger)
	publicMux.Handle("GET /authorize", authorizeHandler)

	tokenHandler := oauth.NewTokenHandler(oauth.TokenConfig{
		Issuer:         cfg.Issuer,
		AccessTokenTTL: cfg.AccessTokenTTL,
		IDTokenTTL:     cfg.IDTokenTTL,
		RefreshIdleTTL: cfg.RefreshIdleTTL,
		RefreshAbsTTL:  cfg.RefreshAbsoluteTTL,
	}, authStore, keyMgr, logger)
	auditWriter := audit.NewWriter(pool)
	tokenHandler.SetAuditWriter(auditWriter)
	publicMux.Handle("POST /token", tokenHandler)

	userinfoHandler := userinfo.NewHandler(tokenValidator, authStore)
	publicMux.Handle("GET /userinfo", userinfoHandler)
	publicMux.Handle("POST /userinfo", userinfoHandler)

	// HTML UI endpoints
	uiHandler := ui.NewHandler(authStore, sessMgr, hasher, auditWriter, logger)
	publicMux.HandleFunc("GET /login", uiHandler.HandleLogin)
	publicMux.HandleFunc("POST /login", uiHandler.HandleLogin)
	publicMux.HandleFunc("GET /register", uiHandler.HandleRegister)
	publicMux.HandleFunc("POST /register", uiHandler.HandleRegister)
	publicMux.HandleFunc("GET /consent", uiHandler.HandleConsent)
	publicMux.HandleFunc("POST /consent", uiHandler.HandleConsent)

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
	adminMux.HandleFunc("GET /readyz", handleReadyz(pool, keyMgr))

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

func handleReadyz(pool *pgxpool.Pool, km *keys.Manager) http.HandlerFunc {
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

		if _, err := km.GetActiveKey(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "unavailable",
				"error":  "no active signing key",
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
