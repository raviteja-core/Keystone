package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactingHandler(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf, slog.LevelInfo)

	logger.Info("user action occurred",
		slog.String("user_id", "123e4567-e89b-12d3-a456-426614174000"),
		slog.String("password", "super-secret-password"),
		slog.String("token", "eyJh...sensitive-token"),
		slog.String("authorization", "Bearer eyJhbG..."),
		slog.String("client_secret", "secret-key-1234"),
		slog.String("normal_param", "safe-value"),
	)

	output := buf.String()

	// Verify plaintext secrets do NOT appear in the log output
	forbidden := []string{
		"super-secret-password",
		"sensitive-token",
		"eyJhbG",
		"secret-key-1234",
	}
	for _, f := range forbidden {
		if strings.Contains(output, f) {
			t.Errorf("found sensitive string %q in log output: %s", f, output)
		}
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("log is not valid JSON: %v", err)
	}

	if parsed["password"] != RedactedPlaceholder {
		t.Errorf("expected redacted password, got %v", parsed["password"])
	}
	if parsed["token"] != RedactedPlaceholder {
		t.Errorf("expected redacted token, got %v", parsed["token"])
	}
	if parsed["authorization"] != RedactedPlaceholder {
		t.Errorf("expected redacted authorization, got %v", parsed["authorization"])
	}
	if parsed["normal_param"] != "safe-value" {
		t.Errorf("expected normal_param preserved, got %v", parsed["normal_param"])
	}
}
