package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ProblemDetails represents an RFC 9457 HTTP Problem Details payload.
type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// WriteProblem writes an RFC 9457 problem+json response.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)

	typeSlug := strings.ToLower(strings.ReplaceAll(title, " ", "-"))
	problem := ProblemDetails{
		Type:     fmt.Sprintf("https://keystone.dev/errors/%s", typeSlug),
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
	}

	_ = json.NewEncoder(w).Encode(problem)
}
