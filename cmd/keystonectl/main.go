package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/auth/audit"
	"github.com/raviteja-core/keystone/internal/auth/keys"
	"github.com/raviteja-core/keystone/internal/auth/password"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/authz/schema"
	authzstore "github.com/raviteja-core/keystone/internal/authz/store"
	"github.com/raviteja-core/keystone/internal/platform/db"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

func getDBPool(ctx context.Context, explicitURL string) (*pgxpool.Pool, error) {
	dbURL := explicitURL
	if dbURL == "" {
		dbURL = os.Getenv("KEYSTONE_AUTH_DB_URL")
	}
	if dbURL == "" {
		dbURL = os.Getenv("KEYSTONE_DB_URL")
	}
	if dbURL == "" {
		port := os.Getenv("KEYSTONE_POSTGRES_PORT")
		if port == "" {
			port = "54320"
		}
		dbURL = "postgres://keystone_auth_app:auth_dev_password@localhost:" + port + "/keystone_auth?sslmode=disable"
	}

	return db.NewPool(ctx, db.DefaultConfig(dbURL))
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "version":
		fmt.Println("keystonectl version 0.1.0")

	case "user":
		if len(os.Args) < 3 {
			fmt.Println("usage: keystonectl user <create> [flags]")
			os.Exit(1)
		}
		subCmd := os.Args[2]
		switch subCmd {
		case "create":
			runUserCreate(os.Args[3:])
		default:
			fmt.Fprintf(os.Stderr, "unknown user command: %s\n", subCmd)
			os.Exit(1)
		}

	case "client":
		if len(os.Args) < 3 {
			fmt.Println("usage: keystonectl client <create> [flags]")
			os.Exit(1)
		}
		subCmd := os.Args[2]
		switch subCmd {
		case "create":
			runClientCreate(os.Args[3:])
		default:
			fmt.Fprintf(os.Stderr, "unknown client command: %s\n", subCmd)
			os.Exit(1)
		}

	case "keys":
		if len(os.Args) < 3 {
			fmt.Println("usage: keystonectl keys <rotate> [flags]")
			os.Exit(1)
		}
		subCmd := os.Args[2]
		switch subCmd {
		case "rotate":
			runKeysRotate(os.Args[3:])
		default:
			fmt.Fprintf(os.Stderr, "unknown keys command: %s\n", subCmd)
			os.Exit(1)
		}

	case "audit":
		if len(os.Args) < 3 {
			fmt.Println("usage: keystonectl audit <verify> [flags]")
			os.Exit(1)
		}
		subCmd := os.Args[2]
		switch subCmd {
		case "verify":
			runAuditVerify(os.Args[3:])
		default:
			fmt.Fprintf(os.Stderr, "unknown audit command: %s\n", subCmd)
			os.Exit(1)
		}

	case "schema":
		if len(os.Args) < 3 {
			fmt.Println("usage: keystonectl schema <push> [flags]")
			os.Exit(1)
		}
		subCmd := os.Args[2]
		switch subCmd {
		case "push":
			runSchemaPush(os.Args[3:])
		default:
			fmt.Fprintf(os.Stderr, "unknown schema command: %s\n", subCmd)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func runUserCreate(args []string) {
	fs := flag.NewFlagSet("user create", flag.ExitOnError)
	email := fs.String("email", "", "User email address (required)")
	plainPass := fs.String("password", "", "User password (minimum 12 characters, required)")
	username := fs.String("username", "", "Optional username")
	displayName := fs.String("display-name", "", "Optional display name")
	dbURL := fs.String("db-url", "", "PostgreSQL database connection URL")
	_ = fs.Parse(args)

	if *email == "" || *plainPass == "" {
		fmt.Fprintln(os.Stderr, "Error: --email and --password are required")
		fs.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hasher, err := password.NewHasher(password.DefaultConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing password hasher: %v\n", err)
		os.Exit(1)
	}

	passHash, err := hasher.Hash(*plainPass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing password: %v\n", err)
		os.Exit(1)
	}

	pool, err := getDBPool(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Database connection error: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	s := store.New(pool)
	uid, err := ids.NewUUIDv7()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating UUID: %v\n", err)
		os.Exit(1)
	}

	var unamePtr, dnamePtr *string
	if *username != "" {
		unamePtr = username
	}
	if *displayName != "" {
		dnamePtr = displayName
	}

	user := &store.User{
		ID:            uid,
		Email:         strings.TrimSpace(strings.ToLower(*email)),
		Username:      unamePtr,
		DisplayName:   dnamePtr,
		PasswordHash:  passHash,
		Status:        "active",
		EmailVerified: true,
	}

	if err := s.CreateUser(ctx, user); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating user: %v\n", err)
		os.Exit(1)
	}

	aw := audit.NewWriter(pool)
	actor := "keystonectl"
	targetType := "user"
	uidStr := user.ID.String()
	_, _ = aw.Record(ctx, audit.Event{
		ActorType:  "admin",
		ActorID:    &actor,
		Action:     audit.ActionUserRegistered,
		TargetType: &targetType,
		TargetID:   &uidStr,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"email": user.Email,
		},
	})

	fmt.Printf("User created successfully:\n  ID:    %s\n  Email: %s\n", user.ID, user.Email)
}

func runClientCreate(args []string) {
	fs := flag.NewFlagSet("client create", flag.ExitOnError)
	clientID := fs.String("client-id", "", "Unique OAuth2 client ID (required)")
	name := fs.String("name", "", "Client application name (required)")
	clientType := fs.String("type", "confidential", "Client type: 'confidential' or 'public'")
	redirectURIs := fs.String("redirect-uris", "", "Comma-separated allowed redirect URIs")
	grantTypes := fs.String("grant-types", "authorization_code,refresh_token", "Comma-separated allowed grant types")
	scopes := fs.String("scopes", "openid,profile,email", "Comma-separated allowed scopes")
	audiences := fs.String("audiences", "", "Comma-separated allowed audiences")
	requireConsent := fs.Bool("require-consent", true, "Require user consent screen")
	dbURL := fs.String("db-url", "", "PostgreSQL database connection URL")
	_ = fs.Parse(args)

	if *clientID == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "Error: --client-id and --name are required")
		fs.Usage()
		os.Exit(1)
	}

	if *clientType != "confidential" && *clientType != "public" {
		fmt.Fprintln(os.Stderr, "Error: --type must be either 'confidential' or 'public'")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := getDBPool(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Database connection error: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	s := store.New(pool)
	cid, err := ids.NewUUIDv7()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating UUID: %v\n", err)
		os.Exit(1)
	}

	var rawSecret string
	var secretHash []byte
	authMethod := "none"

	if *clientType == "confidential" {
		rawSecret, err = ids.RandomBase64URL(32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating client secret: %v\n", err)
			os.Exit(1)
		}
		secretHash = ids.SHA256Digest([]byte(rawSecret))
		authMethod = "client_secret_basic"
	}

	var redirectURIList []string
	if *redirectURIs != "" {
		for _, u := range strings.Split(*redirectURIs, ",") {
			trimmed := strings.TrimSpace(u)
			if trimmed != "" {
				redirectURIList = append(redirectURIList, trimmed)
			}
		}
	}

	var grantTypeList []string
	if *grantTypes != "" {
		for _, g := range strings.Split(*grantTypes, ",") {
			trimmed := strings.TrimSpace(g)
			if trimmed != "" {
				grantTypeList = append(grantTypeList, trimmed)
			}
		}
	}

	var scopeList []string
	if *scopes != "" {
		for _, sc := range strings.Split(*scopes, ",") {
			trimmed := strings.TrimSpace(sc)
			if trimmed != "" {
				scopeList = append(scopeList, trimmed)
			}
		}
	}

	var audienceList []string
	if *audiences != "" {
		for _, a := range strings.Split(*audiences, ",") {
			trimmed := strings.TrimSpace(a)
			if trimmed != "" {
				audienceList = append(audienceList, trimmed)
			}
		}
	}

	client := &store.Client{
		ID:                      cid,
		ClientID:                *clientID,
		ClientSecretHash:        secretHash,
		Name:                    *name,
		ClientType:              *clientType,
		TokenEndpointAuthMethod: authMethod,
		RedirectURIs:            redirectURIList,
		AllowedGrantTypes:       grantTypeList,
		AllowedScopes:           scopeList,
		AllowedAudiences:        audienceList,
		RequireConsent:          *requireConsent,
	}

	if err := s.CreateClient(ctx, client); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	aw := audit.NewWriter(pool)
	actor := "keystonectl"
	targetType := "client"
	_, _ = aw.Record(ctx, audit.Event{
		ActorType:  "admin",
		ActorID:    &actor,
		Action:     audit.ActionClientCreated,
		TargetType: &targetType,
		TargetID:   &client.ClientID,
		Outcome:    audit.OutcomeSuccess,
		Metadata: map[string]any{
			"client_id": client.ClientID,
			"name":      client.Name,
			"type":      client.ClientType,
		},
	})

	fmt.Printf("Client created successfully:\n  ID:        %s\n  ClientID:  %s\n  Type:      %s\n", client.ID, client.ClientID, client.ClientType)
	if *clientType == "confidential" {
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("CLIENT SECRET: %s\n", rawSecret)
		fmt.Println("Save this secret immediately! It is hashed and will NOT be shown again.")
		fmt.Println("--------------------------------------------------------------------------------")
	}
}

func getAuthzDBPool(ctx context.Context, explicitURL string) (*pgxpool.Pool, error) {
	dbURL := explicitURL
	if dbURL == "" {
		dbURL = os.Getenv("KEYSTONE_AUTHZ_DB_URL")
	}
	if dbURL == "" {
		port := os.Getenv("KEYSTONE_POSTGRES_PORT")
		if port == "" {
			port = "54320"
		}
		dbURL = "postgres://keystone_authz_app:authz_dev_password@localhost:" + port + "/keystone_authz?sslmode=disable"
	}

	return db.NewPool(ctx, db.DefaultConfig(dbURL))
}

func runSchemaPush(args []string) {
	fs := flag.NewFlagSet("schema push", flag.ExitOnError)
	file := fs.String("file", "", "Path to schema YAML file (required)")
	tenantID := fs.String("tenant", "", "Tenant ID (required)")
	dbURL := fs.String("db-url", "", "PostgreSQL authz database connection URL")
	_ = fs.Parse(args)

	if *file == "" || *tenantID == "" {
		fmt.Fprintln(os.Stderr, "Error: --file and --tenant are required")
		fs.Usage()
		os.Exit(1)
	}

	content, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read schema file: %v\n", err)
		os.Exit(1)
	}

	sch, err := schema.ParseAndValidate(string(content))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: schema validation failed: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := getAuthzDBPool(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to connect to authz database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Ensure tenant exists
	_, err = pool.Exec(ctx, `
		INSERT INTO authz_tenants (tenant_id, current_rev)
		VALUES ($1, 0)
		ON CONFLICT (tenant_id) DO NOTHING
	`, *tenantID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize tenant: %v\n", err)
		os.Exit(1)
	}

	// Get next version
	var nextVersion int
	err = pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(version), 0) + 1
		FROM authz_schemas
		WHERE tenant_id = $1
	`, *tenantID).Scan(&nextVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to determine schema version: %v\n", err)
		os.Exit(1)
	}

	s := authzstore.New(pool)
	createdRev, err := s.SaveSchema(ctx, *tenantID, nextVersion, string(content), sch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to save schema: %v\n", err)
		os.Exit(1)
	}

	zookie := authzstore.EncodeZookie(*tenantID, createdRev)
	fmt.Printf("Schema version %d successfully pushed for tenant %q (zookie: %s)\n", nextVersion, *tenantID, zookie)
}

func runKeysRotate(args []string) {
	rotateCmd := flag.NewFlagSet("rotate", flag.ExitOnError)
	dbURL := rotateCmd.String("db-url", "", "PostgreSQL database URL")
	bits := rotateCmd.Int("bits", 2048, "RSA key size in bits (2048 or 3072)")
	_ = rotateCmd.Parse(args)

	ctx := context.Background()
	pool, err := getDBPool(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	masterKeyB64 := os.Getenv("KEYSTONE_MASTER_KEY")
	if masterKeyB64 == "" {
		masterKeyB64 = "ta2vI9UdhLTp7Ak2M33C9oSRrdl6riaCkKFL6UDP6Zc="
	}
	masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		masterKey, err = base64.RawURLEncoding.DecodeString(masterKeyB64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid base64 master key: %v\n", err)
			os.Exit(1)
		}
	}

	km, err := keys.NewManager(pool, masterKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize key manager: %v\n", err)
		os.Exit(1)
	}

	newKey, err := km.RotateKey(ctx, *bits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: key rotation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully rotated signing key!\nNew Active Key ID (kid): %s\nAlgorithm: %s\nStatus: %s\nCreated: %s\n",
		newKey.KID, newKey.Algorithm, newKey.Status, newKey.CreatedAt.Format(time.RFC3339))
}

func runAuditVerify(args []string) {
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	dbURL := verifyCmd.String("db-url", "", "PostgreSQL database URL")
	_ = verifyCmd.Parse(args)

	ctx := context.Background()
	pool, err := getDBPool(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	count, err := audit.VerifyChain(ctx, pool)
	if err != nil {
		fmt.Fprintf(os.Stderr, "AUDIT CHAIN INTEGRITY FAILURE: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Audit hash chain verification SUCCESS: %d event records verified with zero tampering detected.\n", count)
}

func printUsage() {
	fmt.Println(`keystonectl — Administrative CLI for Keystone IAM & Authorization Platform

Usage:
  keystonectl <command> [subcommand] [flags]

Available Commands:
  user        Manage users (create)
  client      Manage OAuth 2.0 clients (create)
  keys        Manage cryptographic signing keys (rotate)
  audit       Manage and verify audit event hash chains (verify)
  schema      Manage ReBAC authorization schemas (push)
  version     Display keystonectl version`)
}
