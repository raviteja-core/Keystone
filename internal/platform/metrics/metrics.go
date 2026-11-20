package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTP Metrics
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "keystone",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests processed by Keystone.",
		},
		[]string{"service", "route", "method", "status"},
	)

	HTTPRequestDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "keystone",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "Histogram of HTTP request latencies.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"service", "route", "method"},
	)

	// Auth Server Metrics
	AuthLoginTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "keystone",
			Subsystem: "auth",
			Name:      "login_total",
			Help:      "Total number of login attempts partitioned by result.",
		},
		[]string{"result"},
	)

	TokenIssuedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "keystone",
			Subsystem: "token",
			Name:      "issued_total",
			Help:      "Total number of OAuth 2.0 tokens issued by grant type.",
		},
		[]string{"grant_type"},
	)

	RefreshReuseDetectedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "keystone",
			Subsystem: "refresh",
			Name:      "reuse_detected_total",
			Help:      "Total number of revoked refresh token replay attacks detected.",
		},
	)

	// Authz Zanzibar Metrics
	AuthzCheckTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "keystone",
			Subsystem: "authz",
			Name:      "check_total",
			Help:      "Total number of Zanzibar permission checks evaluated.",
		},
		[]string{"result", "cache"},
	)

	AuthzCheckDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "keystone",
			Subsystem: "authz",
			Name:      "check_duration_seconds",
			Help:      "Histogram of Zanzibar permission check evaluation latencies.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		},
	)

	AuthzWriteTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "keystone",
			Subsystem: "authz",
			Name:      "write_total",
			Help:      "Total number of Zanzibar relationship tuple writes.",
		},
	)
)

func init() {
	prometheus.MustRegister(
		HTTPRequestsTotal,
		HTTPRequestDurationSeconds,
		AuthLoginTotal,
		TokenIssuedTotal,
		RefreshReuseDetectedTotal,
		AuthzCheckTotal,
		AuthzCheckDurationSeconds,
		AuthzWriteTotal,
	)
}

// Handler returns the Prometheus metrics HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}

// Middleware records HTTP request counts and durations for Prometheus.
func Middleware(service string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(ww, r)

			duration := time.Since(start).Seconds()
			route := r.Pattern
			if route == "" {
				route = r.URL.Path
			}

			statusStr := strconv.Itoa(ww.statusCode)
			HTTPRequestsTotal.WithLabelValues(service, route, r.Method, statusStr).Inc()
			HTTPRequestDurationSeconds.WithLabelValues(service, route, r.Method).Observe(duration)
		})
	}
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *statusResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
