package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// RedactedPlaceholder is inserted whenever sensitive data is intercepted.
const RedactedPlaceholder = "[REDACTED]"

var sensitiveKeys = map[string]struct{}{
	"password":           {},
	"password_hash":      {},
	"client_secret":      {},
	"client_secret_hash": {},
	"token":              {},
	"access_token":       {},
	"refresh_token":      {},
	"id_token":           {},
	"code":               {},
	"auth_code":          {},
	"totp_secret":        {},
	"secret_enc":         {},
	"private_enc":        {},
	"master_key":         {},
	"authorization":      {},
	"cookie":             {},
	"set-cookie":         {},
}

// RedactingHandler wraps an slog.Handler to sanitize sensitive keys before writing.
type RedactingHandler struct {
	inner slog.Handler
}

// NewRedactingHandler creates a new RedactingHandler.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	sanitizedRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		sanitizedRecord.AddAttrs(sanitizeAttr(a))
		return true
	})
	return h.inner.Handle(ctx, sanitizedRecord)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	sanitized := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		sanitized[i] = sanitizeAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(sanitized)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func sanitizeAttr(a slog.Attr) slog.Attr {
	normalizedKey := strings.ToLower(strings.TrimSpace(a.Key))
	if _, sensitive := sensitiveKeys[normalizedKey]; sensitive {
		return slog.String(a.Key, RedactedPlaceholder)
	}

	// If value is a group, sanitize recursively
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		sanitized := make([]slog.Attr, len(attrs))
		for i, sub := range attrs {
			sanitized[i] = sanitizeAttr(sub)
		}
		return slog.Attr{
			Key:   a.Key,
			Value: slog.GroupValue(sanitized...),
		}
	}

	return a
}

// NewJSONLogger initializes a production-ready JSON structured logger writing to w.
func NewJSONLogger(w io.Writer, level slog.Level) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}
	opts := &slog.HandlerOptions{
		Level: level,
	}
	jsonHandler := slog.NewJSONHandler(w, opts)
	return slog.New(NewRedactingHandler(jsonHandler))
}
