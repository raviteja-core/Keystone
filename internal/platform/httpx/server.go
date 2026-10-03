package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ServerConfig defines timeout configurations for http.Server.
type ServerConfig struct {
	Addr              string
	Handler           http.Handler
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// DefaultServerConfig returns default production timeouts.
func DefaultServerConfig(addr string, handler http.Handler) ServerConfig {
	return ServerConfig{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
}

// NewServer creates an http.Server with hardened timeouts.
func NewServer(cfg ServerConfig) *http.Server {
	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           cfg.Handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
}

// RunWithGracefulShutdown runs the provided servers and drains requests cleanly upon SIGINT or SIGTERM.
func RunWithGracefulShutdown(logger *slog.Logger, shutdownTimeout time.Duration, servers ...*http.Server) error {
	shutdownErrChan := make(chan error, len(servers))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	for _, srv := range servers {
		go func(s *http.Server) {
			logger.Info("starting http listener", slog.String("addr", s.Addr))
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("server listener error", slog.String("addr", s.Addr), slog.Any("error", err))
				shutdownErrChan <- err
			}
		}(srv)
	}

	select {
	case sig := <-stop:
		logger.Info("received termination signal, initiating graceful shutdown", slog.String("signal", sig.String()))
	case err := <-shutdownErrChan:
		return fmt.Errorf("server listener failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	for _, srv := range servers {
		logger.Info("draining in-flight requests", slog.String("addr", srv.Addr))
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", slog.String("addr", srv.Addr), slog.Any("error", err))
			return fmt.Errorf("graceful shutdown failed for %s: %w", srv.Addr, err)
		}
	}

	logger.Info("all servers drained and stopped successfully")
	return nil
}
