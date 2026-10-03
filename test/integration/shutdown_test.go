package integration

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/raviteja-core/keystone/internal/platform/httpx"
)

func TestGracefulShutdownDrainsInFlightRequests(t *testing.T) {
	// Allocate a free local port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on port: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	inFlightStarted := make(chan struct{})
	inFlightFinished := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(inFlightStarted)
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("drained"))
		close(inFlightFinished)
	})

	srv := httpx.NewServer(httpx.DefaultServerConfig(addr, mux))

	serverErrChan := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrChan <- err
		}
	}()

	// Wait for server to start listening
	time.Sleep(100 * time.Millisecond)

	// Launch in-flight slow request
	client := &http.Client{Timeout: 2 * time.Second}
	var resp *http.Response
	var reqErr error
	reqDone := make(chan struct{})

	go func() {
		resp, reqErr = client.Get("http://" + addr + "/slow")
		close(reqDone)
	}()

	// Wait until the slow request handler has actually started executing
	select {
	case <-inFlightStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for in-flight request to start")
	}

	// Trigger graceful shutdown while the request is in flight
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	logger.Info("triggering server shutdown")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("expected clean shutdown, got %v", err)
	}

	// Wait for in-flight request to complete
	select {
	case <-reqDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for request completion after shutdown")
	}

	if reqErr != nil {
		t.Fatalf("in-flight request failed during drain: %v", reqErr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for drained request, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read drained response body: %v", err)
	}
	if string(body) != "drained" {
		t.Errorf("expected body 'drained', got %q", string(body))
	}
}
