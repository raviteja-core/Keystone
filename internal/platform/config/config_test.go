package config

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

func validMasterKeyB64() string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("KEYSTONE_ISSUER", "http://localhost:8080")
	t.Setenv("KEYSTONE_DB_URL", "postgres://user:pass@localhost:5432/keystone_auth")
	t.Setenv("KEYSTONE_MASTER_KEY", validMasterKeyB64())
}

func TestLoadFromEnv_ValidDevDefaults(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("KEYSTONE_ENV", "dev")

	cfg, err := LoadFromEnv(":8080", ":9100")
	if err != nil {
		t.Fatalf("expected clean load, got error: %v", err)
	}

	if cfg.Env != EnvDev {
		t.Errorf("expected env dev, got %q", cfg.Env)
	}
	if cfg.Issuer != "http://localhost:8080" {
		t.Errorf("unexpected issuer %q", cfg.Issuer)
	}
	if cfg.AccessTokenTTL != 10*time.Minute {
		t.Errorf("unexpected access token TTL: %v", cfg.AccessTokenTTL)
	}
	if len(cfg.MasterKey) != 32 {
		t.Fatalf("expected 32 byte master key, got %d", len(cfg.MasterKey))
	}
}

func TestLoadFromEnv_MissingIssuer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("KEYSTONE_ISSUER", "")

	_, err := LoadFromEnv(":8080", ":9100")
	if err == nil || !strings.Contains(err.Error(), "KEYSTONE_ISSUER is required") {
		t.Fatalf("expected KEYSTONE_ISSUER is required, got %v", err)
	}
}

func TestLoadFromEnv_TrailingSlashIssuer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("KEYSTONE_ISSUER", "http://localhost:8080/")

	_, err := LoadFromEnv(":8080", ":9100")
	if err == nil || !strings.Contains(err.Error(), "trailing slash") {
		t.Fatalf("expected trailing slash rejection, got %v", err)
	}
}

func TestLoadFromEnv_MissingDatabaseURL(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("KEYSTONE_DB_URL", "")

	_, err := LoadFromEnv(":8080", ":9100")
	if err == nil || !strings.Contains(err.Error(), "KEYSTONE_DB_URL is required") {
		t.Fatalf("expected KEYSTONE_DB_URL is required, got %v", err)
	}
}

func TestLoadFromEnv_InvalidMasterKeyLength(t *testing.T) {
	setMinimalEnv(t)
	// 16 bytes encoded instead of 32
	shortKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	t.Setenv("KEYSTONE_MASTER_KEY", shortKey)

	_, err := LoadFromEnv(":8080", ":9100")
	if err == nil || !strings.Contains(err.Error(), "exactly 32 bytes") {
		t.Fatalf("expected 32 bytes error, got %v", err)
	}
}

func TestLoadFromEnv_ProdRefusesInsecureSettings(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T)
		errContains string
	}{
		{
			name: "http issuer in prod",
			setup: func(t *testing.T) {
				t.Setenv("KEYSTONE_ISSUER", "http://auth.example.com")
			},
			errContains: "must use https",
		},
		{
			name: "insecure cookies in prod",
			setup: func(t *testing.T) {
				t.Setenv("KEYSTONE_ISSUER", "https://auth.example.com")
				t.Setenv("KEYSTONE_COOKIE_SECURE", "false")
			},
			errContains: "KEYSTONE_COOKIE_SECURE must be true",
		},
		{
			name: "weak argon2 memory in prod",
			setup: func(t *testing.T) {
				t.Setenv("KEYSTONE_ISSUER", "https://auth.example.com")
				t.Setenv("KEYSTONE_ARGON2_MEMORY_KIB", "8192") // < 19456
			},
			errContains: "at least 19456 KiB",
		},
		{
			name: "weak argon2 time in prod",
			setup: func(t *testing.T) {
				t.Setenv("KEYSTONE_ISSUER", "https://auth.example.com")
				t.Setenv("KEYSTONE_ARGON2_TIME", "1") // < 2
			},
			errContains: "KEYSTONE_ARGON2_TIME must be >= 2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setMinimalEnv(t)
			t.Setenv("KEYSTONE_ENV", "prod")
			tc.setup(t)

			_, err := LoadFromEnv(":8080", ":9100")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errContains)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("expected error containing %q, got %v", tc.errContains, err)
			}
		})
	}
}

func TestLoadFromEnv_MasterKeyFile(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("KEYSTONE_MASTER_KEY", "")

	tmpFile, err := os.CreateTemp("", "master-key-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	key := validMasterKeyB64()
	if _, err := tmpFile.WriteString(key + "\n"); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	t.Setenv("KEYSTONE_MASTER_KEY_FILE", tmpFile.Name())

	cfg, err := LoadFromEnv(":8080", ":9100")
	if err != nil {
		t.Fatalf("failed to load key from file: %v", err)
	}
	if len(cfg.MasterKey) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(cfg.MasterKey))
	}
}
