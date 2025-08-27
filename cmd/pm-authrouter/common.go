package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"pm-authrouter/internal/config"
	"pm-authrouter/internal/system"
)

const (
	httpsPort      = 443
	defaultTimeout = 30
)

// testServerHealth tests the server health before modifying hosts file
func testServerHealth(cfg *config.Config) error {
	// Create a test request to our own server with disabled certificate verification
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 3 * time.Second, // Reduced from 5s for faster retries
	}

	// Test with the actual port we're listening on using our health endpoint
	url := fmt.Sprintf("https://127.0.0.1:%d/health", httpsPort)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}
	
	req.Host = "identity.getpostman.com"

	resp, err := client.Do(req)
	if err != nil {
		// Provide more specific error information
		if strings.Contains(err.Error(), "connection refused") {
			return fmt.Errorf("server not yet accepting connections: %w", err)
		} else if strings.Contains(err.Error(), "timeout") {
			return fmt.Errorf("server health check timed out: %w", err)
		} else if strings.Contains(err.Error(), "tls") {
			return fmt.Errorf("TLS handshake failed (server may be starting): %w", err)
		}
		return fmt.Errorf("health check connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d (expected 200)", resp.StatusCode)
	}

	return nil
}

// waitForServerReady waits for the server to start and become healthy with retry logic
func waitForServerReady(cfg *config.Config, timeout time.Duration) error {
	log.Printf("Waiting for server to become ready (timeout: %v)...", timeout)
	
	start := time.Now()
	backoff := 100 * time.Millisecond
	maxBackoff := 2 * time.Second
	
	for time.Since(start) < timeout {
		// First check if server is listening on the port
		if !isPortListening(httpsPort) {
			log.Printf("Port %d not yet listening, waiting %v...", httpsPort, backoff)
			time.Sleep(backoff)
			
			// Exponential backoff with maximum
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		
		// Port is listening, now test health
		err := testServerHealth(cfg)
		if err == nil {
			elapsed := time.Since(start)
			log.Printf("Server ready after %v", elapsed)
			return nil
		}
		
		log.Printf("Health check failed: %v, retrying in %v...", err, backoff)
		time.Sleep(backoff)
		
		// Exponential backoff with maximum
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	
	elapsed := time.Since(start)
	return fmt.Errorf("server did not become ready within %v (waited %v)", timeout, elapsed)
}

// isPortListening checks if a port is listening for connections
func isPortListening(port int) bool {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	
	// Use net.DialTimeout for a more reliable connection test
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	
	return true
}

// monitorDNSInterception monitors DNS interception integrity with enhanced error recovery
func monitorDNSInterception(ctx context.Context, systemMgr *system.Manager) {
	log.Println("Started DNS interception monitoring")
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("DNS interception monitoring stopped")
			return
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("DNS monitor recovered from panic: %v", r)
					}
				}()

				if !systemMgr.CheckDNSInterception() {
					log.Println("DNS interception appears to have failed, attempting restoration...")
					
					// Get status for diagnosis
					status := systemMgr.GetDNSStatus()
					log.Printf("DNS Status: %+v", status)
					
					// Try to setup DNS interception again
					if err := systemMgr.SetupDNSInterception("identity.getpostman.com"); err != nil {
						log.Printf("Failed to restore DNS interception: %v", err)
						
						// Try fallback to hosts file method only
						time.Sleep(10 * time.Second)
						if !systemMgr.CheckHostsEntry() {
							log.Printf("Falling back to hosts file restoration...")
							if err := systemMgr.RestoreHostsEntry(); err != nil {
								log.Printf("Hosts file fallback failed: %v", err)
							} else {
								log.Println("Hosts file fallback successful")
							}
						}
					} else {
						log.Printf("DNS interception restored using method: %s", systemMgr.GetDNSStatus()["active_method"])
					}
				}
			}()
		}
	}
}