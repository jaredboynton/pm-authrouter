package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"syscall"
	"time"

	"pm-authrouter/internal/config"
)

const (
	// Network constants
	// Bind to loopback only for security - local service should never be externally accessible
	// Use SO_REUSEADDR to handle rapid restarts during testing
	DefaultHost = "127.0.0.1"
	DefaultPort = 443
)

// Server represents the HTTPS proxy server
type Server struct {
	config     *config.Config
	httpServer *http.Server
	handler    *Handler
}

// NewServer creates a new proxy server
func NewServer(cfg *config.Config, certPath, keyPath string) (*Server, error) {
	// Load TLS configuration
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "identity.getpostman.com",
	}

	// Create request handler
	handler := NewHandler(cfg)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", DefaultHost, DefaultPort),
		Handler:      handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return &Server{
		config:     cfg,
		httpServer: server,
		handler:    handler,
	}, nil
}

// Start starts the proxy server
func (s *Server) Start(ctx context.Context) error {
	log.Printf("Starting HTTPS proxy server on %s", s.httpServer.Addr)

	// Create custom listener with SO_REUSEADDR to handle rapid restarts
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR to allow binding to recently-closed ports
				if err := s.setSOReuseAddr(fd); err != nil {
					log.Printf("Warning: failed to set SO_REUSEADDR: %v", err)
				}
			})
		},
	}

	// Create TCP listener with SO_REUSEADDR, using tcp4 for IPv4-only
	listener, err := lc.Listen(ctx, "tcp4", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to create listener on %s: %w", s.httpServer.Addr, err)
	}

	// Wrap with TLS
	tlsListener := tls.NewListener(listener, s.httpServer.TLSConfig)

	// Channel to capture startup errors
	startupErr := make(chan error, 1)
	
	// Start server in goroutine
	go func() {
		// Use Serve instead of ListenAndServeTLS since we have our own listener
		err := s.httpServer.Serve(tlsListener)
		if err != nil && err != http.ErrServerClosed {
			log.Printf("HTTPS server error: %v", err)
			// Send error to channel if startup hasn't completed yet
			select {
			case startupErr <- err:
			default:
			}
		}
	}()

	// Wait briefly for any immediate startup errors
	select {
	case err := <-startupErr:
		listener.Close()
		return fmt.Errorf("failed to start HTTPS server: %w", err)
	case <-time.After(100 * time.Millisecond):
		// No immediate error, assume server started successfully
		log.Printf("HTTPS proxy server listening on %s with SO_REUSEADDR", s.httpServer.Addr)
	}

	// Wait for context cancellation
	<-ctx.Done()

	log.Println("Shutting down HTTPS proxy server...")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
		return err
	}

	log.Println("HTTPS proxy server stopped")
	return nil
}