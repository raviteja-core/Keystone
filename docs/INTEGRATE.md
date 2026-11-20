# Keystone Integration Guide: Go & Java

This guide details how to integrate Keystone Authentication (OAuth 2.0 / OIDC) and Relationship-Based Access Control (ReBAC) into backend microservices using the official **Go SDK** and **Java Spring Boot Starter**.

---

## 1. Go Resource Server Integration (`pkg/keystone`)

### Installation
```bash
go get github.com/raviteja-core/keystone/pkg/keystone
```

### Verifying Tokens & Enforcing Permissions
```go
package main

import (
	"log"
	"net/http"

	"github.com/raviteja-core/keystone/pkg/keystone"
)

func main() {
	// 1. Initialize Token Verifier (Enforces RS256, typ: at+jwt, kid caching)
	verifier := keystone.NewTokenVerifier(keystone.VerifierConfig{
		Issuer:   "http://localhost:8080",
		Audience: "https://api.example.com",
		JWKSURL:  "http://localhost:8080/jwks.json",
	})

	// 2. Initialize Zanzibar Authz Client
	authzClient := keystone.NewAuthzClient(keystone.AuthzConfig{
		BaseURL:  "http://localhost:8081",
		TenantID: "default",
	})

	mux := http.NewServeMux()

	// 3. Protect route with JWT validation and Zanzibar permission check
	mux.HandleFunc("GET /documents/{id}", func(w http.ResponseWriter, r *http.Request) {
		docID := r.PathValue("id")

		// Extract authenticated claims
		claims, ok := keystone.ClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Zanzibar permission evaluation
		allowed, err := authzClient.CheckPermission(r.Context(), keystone.CheckRequest{
			Resource:   keystone.ResourceRef{Type: "document", ID: docID},
			Permission: "view",
			Subject:    keystone.SubjectRef{Type: "user", ID: claims.Subject},
		})
		if err != nil || !allowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		w.Write([]byte(`{"status":"access granted","document_id":"` + docID + `"}`))
	})

	// Wrap router with Keystone Auth Middleware
	handler := keystone.AuthMiddleware(verifier)(mux)
	log.Println("Go resource server listening on :8000")
	http.ListenAndServe(":8000", handler)
}
```

---

## 2. Java & Spring Boot Integration (`keystone-spring-boot-starter`)

### Maven Dependency
```xml
<dependency>
    <groupId>io.github.raviteja-core</groupId>
    <artifactId>keystone-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

### Configuration (`application.yml`)
```yaml
keystone:
  auth:
    issuer-url: http://localhost:8080
    audience: https://api.example.com
  authz:
    base-url: http://localhost:8081
    tenant-id: default
    cache:
      enabled: true
      maximum-size: 10000
      ttl: 60s
```

### Declarative Method Security (`@RequiresPermission`)
```java
package com.example.demo;

import io.github.raviteja-core.keystone.autoconfigure.security.RequiresPermission;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    @GetMapping("/{id}")
    @RequiresPermission(
        resourceType = "doc",
        resourceId = "#id",
        permission = "view"
    )
    public Document getDocument(@PathVariable String id) {
        return new Document(id, "Top Secret Report");
    }

    @DeleteMapping("/{id}")
    @RequiresPermission(
        resourceType = "doc",
        resourceId = "#id",
        permission = "owner"
    )
    public void deleteDocument(@PathVariable String id) {
        // Only owners may delete
    }
}
```

### Consistency & Zookie Tracking
The Spring Boot Starter automatically captures `X-Keystone-Zookie` response headers from write operations and tracks the latest revision monotonically. Subsequent `@RequiresPermission` evaluations automatically send `at_least_as_fresh(latestZookie)` to prevent stale read anomalies across microservice replicas.
