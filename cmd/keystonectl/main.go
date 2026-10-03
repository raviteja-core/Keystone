package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/auth/audit"
	"github.com/raviteja-core/keystone/internal/auth/password"
	"github.com/raviteja-core/keystone/internal/auth/store"
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
		keysCmd := flag.NewFlagSet("keys", flag.ExitOnError)
		if len(os.Args) < 3 {
			fmt.Println("usage: keystonectl keys <rotate>")
			os.Exit(1)
		}
		_ = keysCmd.Parse(os.Args[3:])
		fmt.Printf("keystonectl: keys %s ready for Phase 1\n", os.Args[2])

	case "audit":
		auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)
		if len(os.Args) < 3 {
			fmt.Println("usage: keystonectl audit <verify>")
			os.Exit(1)
		}
		_ = auditCmd.Parse(os.Args[3:])
		fmt.Printf("keystonectl: audit %s ready for Phase 4\n", os.Args[2])

	case "schema":
		schemaCmd := flag.NewFlagSet("schema", flag.ExitOnError)
		if len(os.Args) < 3 {
			fmt.Println("usage: keystonectl schema <push>")
			os.Exit(1)
		}
		_ = schemaCmd.Parse(os.Args[3:])
		fmt.Printf("keystonectl: schema %s ready for Phase 2\n", os.Args[2])

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
