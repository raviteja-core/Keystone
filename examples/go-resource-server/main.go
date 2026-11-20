package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/raviteja-core/keystone/pkg/keystone"
)

func main() {
	issuerURL := getEnv("KEYSTONE_ISSUER_URL", "http://localhost:8080")
	audience := getEnv("KEYSTONE_AUDIENCE", "demo-docs")
	authzURL := getEnv("KEYSTONE_AUTHZ_URL", "http://localhost:8081")
	clientID := getEnv("KEYSTONE_CLIENT_ID", "demo-client")
	clientSecret := getEnv("KEYSTONE_CLIENT_SECRET", "demo-secret")

	// 1. Initialize JWT Access Token Verifier (OIDC JWKS)
	verifier, err := keystone.NewVerifier(issuerURL, audience)
	if err != nil {
		log.Fatalf("failed to initialize token verifier: %v", err)
	}

	// 2. Initialize Authz ReBAC Client
	tokenSource := keystone.ClientCredentialsTokenSource(
		issuerURL+"/token",
		clientID,
		clientSecret,
		"authz:check authz:write",
	)
	authzClient, err := keystone.NewAuthzClient(authzURL, tokenSource)
	if err != nil {
		log.Fatalf("failed to initialize authz client: %v", err)
	}

	mux := http.NewServeMux()

	// Public health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Protected document endpoints
	docsMux := http.NewServeMux()

	// GET /docs/{id} requires "view" permission on object doc:{id}
	docsMux.HandleFunc("GET /docs/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		claims, _ := keystone.ClaimsFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":        id,
			"title":     fmt.Sprintf("Secret Document %s", id),
			"viewed_by": claims.Subject,
		})
	})

	// PUT /docs/{id} requires "edit" permission on object doc:{id}
	docsMux.HandleFunc("PUT /docs/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		claims, _ := keystone.ClaimsFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":        id,
			"status":    "updated",
			"edited_by": claims.Subject,
		})
	})

	// Permission extractor for document routes
	docPermissionExtractor := func(r *http.Request) (keystone.ObjectRef, string, *keystone.SubjectRef, error) {
		id := r.PathValue("id")
		if id == "" {
			return keystone.ObjectRef{}, "", nil, fmt.Errorf("document ID is required")
		}
		var perm string
		switch r.Method {
		case http.MethodGet:
			perm = "view"
		case http.MethodPut:
			perm = "edit"
		case http.MethodDelete:
			perm = "delete"
		default:
			perm = "view"
		}
		// Returning nil for SubjectRef lets Keystone resolve subject automatically from JWT sub claims
		return keystone.ObjectRef{Type: "document", ID: id}, perm, nil, nil
	}

	// Chain middlewares: Authentication (JWT) -> Authorization (ReBAC) -> Handlers
	authMiddleware := keystone.Middleware(verifier)
	authzMiddleware := keystone.RequirePermission(authzClient, docPermissionExtractor)

	mux.Handle("/docs/", authMiddleware(authzMiddleware(docsMux)))

	port := getEnv("PORT", "8082")
	log.Printf("Keystone protected resource server listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("server terminated: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
