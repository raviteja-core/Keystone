package store_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/platform/db"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

func getTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("KEYSTONE_DB_URL")
	if dbURL == "" {
		port := os.Getenv("KEYSTONE_POSTGRES_PORT")
		if port == "" {
			port = "54320"
		}
		dbURL = "postgres://keystone_auth_app:auth_dev_password@localhost:" + port + "/keystone_auth?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pool, err := db.NewPool(ctx, db.DefaultConfig(dbURL))
	if err != nil {
		t.Skipf("skipping store integration test: PostgreSQL not available: %v", err)
	}

	return pool
}

func TestStore_UserCRUD(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, err := ids.NewUUIDv7()
	if err != nil {
		t.Fatalf("failed to generate uuid: %v", err)
	}

	username := "alice_" + strings.ReplaceAll(uid.String(), "-", "")
	u := &store.User{
		ID:           uid,
		Email:        username + "@example.com",
		Username:     &username,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$test$test",
		Status:       "active",
		Version:      1,
	}

	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Fetch by ID
	fetched, err := s.GetUserByID(ctx, uid)
	if err != nil {
		t.Fatalf("failed to get user by id: %v", err)
	}
	if fetched.Email != u.Email {
		t.Errorf("expected email %q, got %q", u.Email, fetched.Email)
	}

	// Fetch by Email (case-insensitive)
	byEmail, err := s.GetUserByEmail(ctx, strings.ToUpper(u.Email))
	if err != nil {
		t.Fatalf("failed to get user by case-insensitive email: %v", err)
	}
	if byEmail.ID != uid {
		t.Errorf("expected id %v, got %v", uid, byEmail.ID)
	}

	// Update password
	newHash := "$argon2id$v=19$m=65536,t=3,p=2$new$new"
	if err := s.UpdateUserPassword(ctx, uid, newHash); err != nil {
		t.Fatalf("failed to update password: %v", err)
	}

	updated, err := s.GetUserByID(ctx, uid)
	if err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if updated.PasswordHash != newHash {
		t.Errorf("expected new hash, got %q", updated.PasswordHash)
	}
	if updated.Version != 2 {
		t.Errorf("expected version 2, got %d", updated.Version)
	}

	// Increment failed login and reset
	if err := s.IncrementFailedLogin(ctx, uid, nil); err != nil {
		t.Fatalf("failed to increment failed login: %v", err)
	}
	uAfterFail, _ := s.GetUserByID(ctx, uid)
	if uAfterFail.FailedLoginCount != 1 {
		t.Errorf("expected failed_login_count 1, got %d", uAfterFail.FailedLoginCount)
	}

	if err := s.ResetFailedLogin(ctx, uid); err != nil {
		t.Fatalf("failed to reset failed login: %v", err)
	}
	uAfterReset, _ := s.GetUserByID(ctx, uid)
	if uAfterReset.FailedLoginCount != 0 {
		t.Errorf("expected failed_login_count 0, got %d", uAfterReset.FailedLoginCount)
	}
}

func TestStore_ClientCRUD(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	clientID := "client_" + strings.ReplaceAll(uid.String(), "-", "")
	secretHash := ids.SHA256Digest([]byte("test_secret"))

	c := &store.Client{
		ID:                      uid,
		ClientID:                clientID,
		ClientSecretHash:        secretHash,
		Name:                    "Test Client",
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		AllowedGrantTypes:       []string{"authorization_code", "refresh_token"},
		AllowedScopes:           []string{"openid", "profile", "email"},
		AllowedAudiences:        []string{"https://api.example.com"},
		RequireConsent:          true,
	}

	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	fetched, err := s.GetClientByID(ctx, clientID)
	if err != nil {
		t.Fatalf("failed to get client by id: %v", err)
	}
	if fetched.Name != c.Name {
		t.Errorf("expected name %q, got %q", c.Name, fetched.Name)
	}
	if len(fetched.RedirectURIs) != 1 || fetched.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("unexpected redirect uris: %v", fetched.RedirectURIs)
	}
}

func TestStore_AuthCodeSingleUseAndAtomicConsumption(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	u := &store.User{
		ID:           uid,
		Email:        "code_test_" + strings.ReplaceAll(uid.String(), "-", "") + "@example.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$test$test",
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	cid, _ := ids.NewUUIDv7()
	clientID := "code_client_" + strings.ReplaceAll(cid.String(), "-", "")
	c := &store.Client{
		ID:                      cid,
		ClientID:                clientID,
		Name:                    "Code Client",
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://client.example.com/cb"},
		AllowedGrantTypes:       []string{"authorization_code"},
		AllowedScopes:           []string{"openid"},
		RequireConsent:          false,
	}
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	codeRaw, _ := ids.RandomBase64URL(32)
	codeHash := ids.SHA256Digest([]byte(codeRaw))

	authCode := &store.AuthorizationCode{
		CodeHash:      codeHash,
		ClientID:      clientID,
		UserID:        uid,
		RedirectURI:   "https://client.example.com/cb",
		Scope:         "openid",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		AuthTime:      time.Now(),
		AMR:           []string{"pwd"},
		ExpiresAt:     time.Now().Add(60 * time.Second),
	}

	if err := s.CreateAuthCode(ctx, authCode); err != nil {
		t.Fatalf("failed to create auth code: %v", err)
	}

	// 50 parallel redemptions of the exact same code
	const workers = 50
	var wg sync.WaitGroup
	results := make([]error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := s.ConsumeAuthCode(ctx, codeHash)
			results[idx] = err
		}(i)
	}
	wg.Wait()

	successCount := 0
	alreadyUsedCount := 0
	for _, res := range results {
		if res == nil {
			successCount++
		} else if res == store.ErrCodeAlreadyUsed {
			alreadyUsedCount++
		}
	}

	if successCount != 1 {
		t.Fatalf("expected exactly 1 success in parallel redemptions, got %d (alreadyUsed: %d)", successCount, alreadyUsedCount)
	}

	// Subsequent redemption must return ErrCodeAlreadyUsed
	_, checkErr := s.ConsumeAuthCode(ctx, codeHash)
	if checkErr != store.ErrCodeAlreadyUsed {
		t.Fatalf("expected ErrCodeAlreadyUsed, got %v", checkErr)
	}
}

func TestStore_RefreshTokenRotationAndFamilyRevocation(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	u := &store.User{
		ID:           uid,
		Email:        "rt_test_" + strings.ReplaceAll(uid.String(), "-", "") + "@example.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$test$test",
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	cid, _ := ids.NewUUIDv7()
	clientID := "rt_client_" + strings.ReplaceAll(cid.String(), "-", "")
	c := &store.Client{
		ID:                      cid,
		ClientID:                clientID,
		Name:                    "RT Client",
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://client.example.com/cb"},
		AllowedGrantTypes:       []string{"refresh_token"},
		AllowedScopes:           []string{"openid"},
		RequireConsent:          false,
	}
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	rt1ID, _ := ids.NewUUIDv7()
	familyID, _ := ids.NewUUIDv7()
	rt1Raw, _ := ids.RandomBase64URL(32)
	rt1Hash := ids.SHA256Digest([]byte(rt1Raw))

	rt1 := &store.RefreshToken{
		ID:                rt1ID,
		TokenHash:         rt1Hash,
		FamilyID:          familyID,
		ClientID:          clientID,
		UserID:            uid,
		Scope:             "openid",
		ExpiresAt:         time.Now().Add(24 * time.Hour),
		AbsoluteExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}
	if err := s.CreateRefreshToken(ctx, rt1); err != nil {
		t.Fatalf("failed to create rt1: %v", err)
	}

	// 50 parallel refreshes with RT1 -> exactly one success
	const workers = 50
	var wg sync.WaitGroup
	successTokens := make([]*store.RefreshToken, workers)
	errorsList := make([]error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				errorsList[idx] = err
				return
			}
			defer tx.Rollback(ctx) //nolint:errcheck

			childID, _ := ids.NewUUIDv7()
			childRaw, _ := ids.RandomBase64URL(32)
			childHash := ids.SHA256Digest([]byte(childRaw))
			child := &store.RefreshToken{
				ID:                childID,
				TokenHash:         childHash,
				ClientID:          clientID,
				UserID:            uid,
				Scope:             "openid",
				ExpiresAt:         time.Now().Add(24 * time.Hour),
				AbsoluteExpiresAt: time.Now().Add(90 * 24 * time.Hour),
			}

			old, rotErr := s.RotateRefreshTokenTx(ctx, tx, rt1Hash, child)
			if rotErr != nil {
				errorsList[idx] = rotErr
				return
			}
			if err := tx.Commit(ctx); err != nil {
				errorsList[idx] = err
				return
			}
			successTokens[idx] = old
		}(i)
	}
	wg.Wait()

	successCount := 0
	for _, tok := range successTokens {
		if tok != nil {
			successCount++
		}
	}

	if successCount != 1 {
		t.Fatalf("expected exactly 1 success in 50 parallel refreshes, got %d", successCount)
	}

	// Replaying RT1 again MUST trigger reuse detection and revoke the whole family
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("failed to begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	childID, _ := ids.NewUUIDv7()
	childRaw, _ := ids.RandomBase64URL(32)
	childHash := ids.SHA256Digest([]byte(childRaw))
	child := &store.RefreshToken{
		ID:        childID,
		TokenHash: childHash,
	}

	_, replayErr := s.RotateRefreshTokenTx(ctx, tx, rt1Hash, child)
	if replayErr == nil {
		t.Fatalf("expected error on replaying rotated RT1, got nil")
	}
	_ = tx.Commit(ctx)

	// Verify all tokens in family are now marked revoked
	var revokedCount int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM refresh_tokens WHERE family_id = $1 AND revoked_at IS NOT NULL", familyID).Scan(&revokedCount)
	if err != nil {
		t.Fatalf("failed to query revoked count: %v", err)
	}
	if revokedCount < 2 {
		t.Fatalf("expected all tokens in family to be revoked, got %d", revokedCount)
	}
}
