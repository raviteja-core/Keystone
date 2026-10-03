package httpx

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestIDMiddleware(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := GetRequestID(r.Context())
		if reqID == "" {
			t.Error("expected non-empty request id in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	handler.ServeHTTP(rec, req)

	respID := rec.Header().Get(RequestIDHeader)
	if respID == "" {
		t.Error("expected X-Request-ID in response header")
	}

	// Test propagating incoming Request ID
	customID := "client-trace-12345"
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set(RequestIDHeader, customID)
	handler.ServeHTTP(rec2, req2)

	if rec2.Header().Get(RequestIDHeader) != customID {
		t.Errorf("expected propagated ID %q, got %q", customID, rec2.Header().Get(RequestIDHeader))
	}
}

func TestRecoverMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	panicHandler := Recover(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulated fatal crash")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/panic", nil)

	panicHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error, got %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "internal_server_error") {
		t.Errorf("expected generic error JSON, got %s", rec.Body.String())
	}

	if !strings.Contains(buf.String(), "panic recovered") {
		t.Errorf("expected panic log entry, got %s", buf.String())
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/secure", nil)
	handler.ServeHTTP(rec, req)

	h := rec.Header()
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("missing or invalid CSP: %s", h.Get("Content-Security-Policy"))
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing nosniff header: %s", h.Get("X-Content-Type-Options"))
	}
	if h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("missing no-referrer header: %s", h.Get("Referrer-Policy"))
	}
	if h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing DENY frame options: %s", h.Get("X-Frame-Options"))
	}
}

func TestMaxBodyBytes(t *testing.T) {
	maxBytes := int64(10)
	handler := MaxBodyBytes(maxBytes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Valid payload within limit
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/upload", strings.NewReader("12345"))
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Errorf("expected 200 for 5 bytes, got %d", rec1.Code)
	}

	// Payload exceeding limit
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/upload", strings.NewReader("123456789012345"))
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 Request Entity Too Large, got %d", rec2.Code)
	}
}
