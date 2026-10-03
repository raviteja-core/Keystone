package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment modes
const (
	EnvDev  = "dev"
	EnvProd = "prod"
)

// Config represents runtime configuration loaded from environment variables.
type Config struct {
	Env                 string
	Issuer              string
	HTTPAddr            string
	AdminAddr           string
	DatabaseURL         string
	MasterKey           []byte // 32-byte key decoded from base64
	CookieSecure        bool
	AccessTokenTTL      time.Duration
	IDTokenTTL          time.Duration
	AuthCodeTTL         time.Duration
	RefreshIdleTTL      time.Duration
	RefreshAbsoluteTTL  time.Duration
	RefreshReuseGrace   time.Duration
	SessionIdleTTL      time.Duration
	SessionAbsoluteTTL  time.Duration
	Argon2MemoryKiB     uint32
	Argon2Time          uint32
	Argon2Parallelism   uint8
	Argon2MaxConcurrent int
	TrustedProxies      []string
}

// LoadFromEnv loads configuration from environment variables and validates values.
func LoadFromEnv(serviceDefaultHTTPAddr, serviceDefaultAdminAddr string) (*Config, error) {
	env := getEnv("KEYSTONE_ENV", EnvDev)
	if env != EnvDev && env != EnvProd {
		return nil, fmt.Errorf("invalid KEYSTONE_ENV: must be %q or %q, got %q", EnvDev, EnvProd, env)
	}

	issuer := os.Getenv("KEYSTONE_ISSUER")
	if issuer == "" {
		return nil, errors.New("KEYSTONE_ISSUER is required")
	}
	if strings.HasSuffix(issuer, "/") {
		return nil, errors.New("KEYSTONE_ISSUER must not have a trailing slash")
	}

	parsedIssuer, err := url.Parse(issuer)
	if err != nil || parsedIssuer.Scheme == "" || parsedIssuer.Host == "" {
		return nil, fmt.Errorf("KEYSTONE_ISSUER must be a valid absolute URI: %w", err)
	}

	if env == EnvProd && parsedIssuer.Scheme != "https" {
		return nil, fmt.Errorf("in production, KEYSTONE_ISSUER must use https: got %q", issuer)
	}

	httpAddr := getEnv("KEYSTONE_HTTP_ADDR", serviceDefaultHTTPAddr)
	adminAddr := getEnv("KEYSTONE_ADMIN_ADDR", serviceDefaultAdminAddr)

	dbURL := os.Getenv("KEYSTONE_DB_URL")
	if dbURL == "" {
		return nil, errors.New("KEYSTONE_DB_URL is required")
	}

	masterKeyB64 := os.Getenv("KEYSTONE_MASTER_KEY")
	if masterKeyB64 == "" {
		// Check KEYSTONE_MASTER_KEY_FILE
		if keyPath := os.Getenv("KEYSTONE_MASTER_KEY_FILE"); keyPath != "" {
			data, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read KEYSTONE_MASTER_KEY_FILE %q: %w", keyPath, err)
			}
			masterKeyB64 = strings.TrimSpace(string(data))
		}
	}

	if masterKeyB64 == "" {
		return nil, errors.New("KEYSTONE_MASTER_KEY (or KEYSTONE_MASTER_KEY_FILE) is required")
	}

	masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		// Try URL-safe base64
		masterKey, err = base64.RawURLEncoding.DecodeString(masterKeyB64)
		if err != nil {
			return nil, fmt.Errorf("KEYSTONE_MASTER_KEY is not valid base64: %w", err)
		}
	}

	if len(masterKey) != 32 {
		return nil, fmt.Errorf("KEYSTONE_MASTER_KEY must decode to exactly 32 bytes, got %d", len(masterKey))
	}

	cookieSecure := true
	if val := os.Getenv("KEYSTONE_COOKIE_SECURE"); val != "" {
		parsedBool, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("invalid KEYSTONE_COOKIE_SECURE: %w", err)
		}
		cookieSecure = parsedBool
	}
	if env == EnvProd && !cookieSecure {
		return nil, errors.New("in production, KEYSTONE_COOKIE_SECURE must be true")
	}

	accessTokenTTL, err := parseDurationEnv("KEYSTONE_ACCESS_TOKEN_TTL", 10*time.Minute)
	if err != nil {
		return nil, err
	}
	if accessTokenTTL < time.Minute || accessTokenTTL > time.Hour {
		return nil, fmt.Errorf("KEYSTONE_ACCESS_TOKEN_TTL must be between 1m and 1h: got %v", accessTokenTTL)
	}

	idTokenTTL, err := parseDurationEnv("KEYSTONE_ID_TOKEN_TTL", 10*time.Minute)
	if err != nil {
		return nil, err
	}

	authCodeTTL, err := parseDurationEnv("KEYSTONE_AUTH_CODE_TTL", 60*time.Second)
	if err != nil {
		return nil, err
	}
	if authCodeTTL <= 0 || authCodeTTL > 10*time.Minute {
		return nil, fmt.Errorf("KEYSTONE_AUTH_CODE_TTL must be positive and <= 10m: got %v", authCodeTTL)
	}

	refreshIdleTTL, err := parseDurationEnv("KEYSTONE_REFRESH_IDLE_TTL", 720*time.Hour)
	if err != nil {
		return nil, err
	}

	refreshAbsoluteTTL, err := parseDurationEnv("KEYSTONE_REFRESH_ABSOLUTE_TTL", 2160*time.Hour)
	if err != nil {
		return nil, err
	}

	refreshReuseGrace, err := parseDurationEnv("KEYSTONE_REFRESH_REUSE_GRACE", 0)
	if err != nil {
		return nil, err
	}
	if refreshReuseGrace < 0 || refreshReuseGrace > 10*time.Second {
		return nil, fmt.Errorf("KEYSTONE_REFRESH_REUSE_GRACE must be between 0s and 10s: got %v", refreshReuseGrace)
	}

	sessionIdleTTL, err := parseDurationEnv("KEYSTONE_SESSION_IDLE_TTL", 30*time.Minute)
	if err != nil {
		return nil, err
	}

	sessionAbsoluteTTL, err := parseDurationEnv("KEYSTONE_SESSION_ABSOLUTE_TTL", 12*time.Hour)
	if err != nil {
		return nil, err
	}

	argon2MemoryKiB, err := parseUint32Env("KEYSTONE_ARGON2_MEMORY_KIB", 65536)
	if err != nil {
		return nil, err
	}
	// OWASP recommended minimum is 19 MiB = 19456 KiB
	if argon2MemoryKiB < 19456 {
		if env == EnvProd {
			return nil, fmt.Errorf("in production, KEYSTONE_ARGON2_MEMORY_KIB must be at least 19456 KiB (19 MiB): got %d", argon2MemoryKiB)
		}
	}

	argon2Time, err := parseUint32Env("KEYSTONE_ARGON2_TIME", 3)
	if err != nil {
		return nil, err
	}
	if argon2Time < 1 {
		return nil, errors.New("KEYSTONE_ARGON2_TIME must be >= 1")
	}
	if env == EnvProd && argon2Time < 2 {
		return nil, fmt.Errorf("in production, KEYSTONE_ARGON2_TIME must be >= 2: got %d", argon2Time)
	}

	argon2ParallelismUint, err := parseUint32Env("KEYSTONE_ARGON2_PARALLELISM", 2)
	if err != nil {
		return nil, err
	}
	if argon2ParallelismUint < 1 || argon2ParallelismUint > 255 {
		return nil, errors.New("KEYSTONE_ARGON2_PARALLELISM must be between 1 and 255")
	}

	argon2MaxConcurrent, err := parseIntEnv("KEYSTONE_ARGON2_MAX_CONCURRENT", 4)
	if err != nil {
		return nil, err
	}
	if argon2MaxConcurrent < 1 {
		return nil, errors.New("KEYSTONE_ARGON2_MAX_CONCURRENT must be >= 1")
	}

	var trustedProxies []string
	if tp := os.Getenv("KEYSTONE_TRUSTED_PROXIES"); tp != "" {
		parts := strings.Split(tp, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				trustedProxies = append(trustedProxies, trimmed)
			}
		}
	}

	return &Config{
		Env:                 env,
		Issuer:              issuer,
		HTTPAddr:            httpAddr,
		AdminAddr:           adminAddr,
		DatabaseURL:         dbURL,
		MasterKey:           masterKey,
		CookieSecure:        cookieSecure,
		AccessTokenTTL:      accessTokenTTL,
		IDTokenTTL:          idTokenTTL,
		AuthCodeTTL:         authCodeTTL,
		RefreshIdleTTL:      refreshIdleTTL,
		RefreshAbsoluteTTL:  refreshAbsoluteTTL,
		RefreshReuseGrace:   refreshReuseGrace,
		SessionIdleTTL:      sessionIdleTTL,
		SessionAbsoluteTTL:  sessionAbsoluteTTL,
		Argon2MemoryKiB:     argon2MemoryKiB,
		Argon2Time:          argon2Time,
		Argon2Parallelism:   uint8(argon2ParallelismUint),
		Argon2MaxConcurrent: argon2MaxConcurrent,
		TrustedProxies:      trustedProxies,
	}, nil
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func parseDurationEnv(key string, defaultVal time.Duration) (time.Duration, error) {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal, nil
	}
	dur, err := time.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s: %w", key, err)
	}
	return dur, nil
}

func parseUint32Env(key string, defaultVal uint32) (uint32, error) {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal, nil
	}
	n, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s: %w", key, err)
	}
	return uint32(n), nil
}

func parseIntEnv(key string, defaultVal int) (int, error) {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s: %w", key, err)
	}
	return n, nil
}
