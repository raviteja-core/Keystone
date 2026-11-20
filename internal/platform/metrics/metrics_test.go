package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/raviteja-core/keystone/internal/platform/metrics"
)

func TestMetrics_MiddlewareAndHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /test-route", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	wrapped := metrics.Middleware("test-service")(mux)

	// Make request
	req := httptest.NewRequest("GET", "/test-route", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Verify metrics endpoint produces output
	metricsHandler := metrics.Handler()
	reqMetrics := httptest.NewRequest("GET", "/metrics", nil)
	recMetrics := httptest.NewRecorder()
	metricsHandler.ServeHTTP(recMetrics, reqMetrics)

	body := recMetrics.Body.String()
	if !strings.Contains(body, "keystone_http_requests_total") {
		t.Errorf("metrics output missing keystone_http_requests_total")
	}
	if !strings.Contains(body, "test-service") {
		t.Errorf("metrics output missing service label")
	}
}
