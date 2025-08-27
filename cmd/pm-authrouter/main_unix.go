//go:build !windows

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"pm-authrouter/internal/config"
	"pm-authrouter/internal/proxy"
	"pm-authrouter/internal/system"
	tlsmgr "pm-authrouter/internal/tls"
)

func main() {
	// Define command line flags - these are accessed by the config package
	_ = flag.String("team", "", "Postman team name")
	_ = flag.String("saml-url", "", "SAML initialization URL")
	flag.Parse()
	
	// Set up logging
	log.SetPrefix("[pm-authrouter] ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("Starting Postman AuthRouter...")

	// Check for required privileges
	if err := checkPrivileges(); err != nil {
		log.Fatalf("Privilege check failed: %v", err)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Loaded configuration for team: %s", cfg.TeamName)

	// Check for and terminate any existing daemon instances before starting
	log.Println("Checking for existing daemon instances...")
	processMgr := system.NewProcessManager()
	existingPIDs, err := processMgr.FindRunningDaemons(httpsPort)
	if err != nil {
		log.Printf("Warning: Error checking for existing daemons: %v", err)
	} else if len(existingPIDs) > 0 {
		log.Printf("Found %d existing daemon process(es). Terminating gracefully...", len(existingPIDs))
		if err := processMgr.TerminateExistingDaemons(existingPIDs); err != nil {
			log.Printf("Warning: Error terminating existing daemons: %v", err)
		}
		log.Println("Existing daemon instances terminated.")
	} else {
		log.Println("No existing daemon instances found.")
	}

	// Set up system integration (hosts file, etc.)
	systemMgr := system.NewManager()

	// Clean up any stale hosts entries from previous instances
	if err := systemMgr.CleanupStaleHostsEntries(); err != nil {
		log.Printf("Warning: Failed to cleanup stale hosts entries: %v", err)
	}

	// Set up TLS certificate management
	tlsMgr := tlsmgr.NewManager(cfg)
	
	// Clean up old certificates first
	// TODO: Implement CleanupOldCertificates method
	// if err := tlsMgr.CleanupOldCertificates(); err != nil {
	// 	log.Printf("Warning: Failed to cleanup old certificates: %v", err)
	// }

	// Generate/validate certificates and install to system trust store
	certPath, keyPath, err := tlsMgr.EnsureValidCertificates()
	if err != nil {
		log.Fatalf("Failed to set up SSL certificates: %v", err)
	}

	// Check if certificate has expired - if so, run in disabled mode
	if cfg.CertificateExpired {
		log.Println("============================================")
		log.Println("CERTIFICATE EXPIRED - RUNNING IN DISABLED MODE")
		log.Println("SAML enforcement is OFF to prevent breaking Postman")
		log.Println("Please contact IT to deploy an updated certificate")
		log.Println("============================================")
		
		// Remove hosts file entry so Postman works normally
		if err := systemMgr.CleanupStaleHostsEntries(); err != nil {
			log.Printf("Warning: Failed to cleanup hosts entries: %v", err)
		}
		
		// Keep running but do nothing (satisfy KeepAlive)
		// Log a reminder every hour
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		
		for {
			select {
			case <-ticker.C:
				log.Println("REMINDER: Certificate expired - SAML enforcement disabled")
			case <-sigChan:
				log.Println("Shutdown signal received")
				return
			}
		}
	}

	// Create HTTPS proxy server
	proxyServer, err := proxy.NewServer(cfg, certPath, keyPath)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Start the proxy server
	serverStarted := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := proxyServer.Start(ctx); err != nil {
			log.Printf("Proxy server error: %v", err)
			// Send error if server hasn't started yet
			select {
			case serverStarted <- err:
			default:
			}
		}
	}()

	// Wait for server to start with proper error handling
	log.Println("Waiting for HTTPS server to start...")
	select {
	case err := <-serverStarted:
		// Server failed to start immediately
		log.Fatalf("Failed to start proxy server: %v", err)
	case <-time.After(500 * time.Millisecond):
		// Server started, now wait for it to be ready
		log.Println("HTTPS server started, waiting for it to become ready...")
	}

	// Use improved wait function with retries
	if err := waitForServerReady(cfg, 10*time.Second); err != nil {
		log.Fatalf("Server did not become ready: %v", err)
	}

	log.Println("HTTPS proxy server is ready")

	// Determine initial trust and act once
	trusted := tlsMgr.IsCertificateTrusted()
	dnsMonitorStarted := false
	
	// Allow bypass for development/debugging
	if os.Getenv("PM_AUTHROUTER_SKIP_CERT_CHECK") == "1" {
		log.Println("WARNING: Certificate trust bypass enabled (PM_AUTHROUTER_SKIP_CERT_CHECK=1)")
		trusted = true
	}
	
	if !trusted {
		log.Println("WARNING: Certificate is not trusted in system keychain")
		log.Println("DNS interception DISABLED to prevent authentication issues")
		log.Println("")
		log.Println("To enable SAML enforcement, you must trust the certificate:")
		log.Println("  Option 1: Manually trust in Keychain Access (macOS) or Certificate Manager (Windows)")
		log.Println("  Option 2: Deploy via MDM/Configuration Profile")
		log.Println("  Option 3: Re-run installer with administrator privileges")
		log.Println("")
		log.Println("AuthRouter is running but NOT intercepting traffic")
		log.Println("DNS interception will enable automatically once certificate is trusted")
	} else {
		log.Println("Certificate is trusted (or bypassed), enabling DNS interception...")
		if err := systemMgr.SetupDNSInterception("identity.getpostman.com"); err != nil {
			log.Printf("Failed to setup DNS interception: %v", err)
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				monitorDNSInterception(ctx, systemMgr)
			}()
			dnsMonitorStarted = true
		}
	}
	
	// Poll for trust changes and toggle DNS interception dynamically
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		lastTrusted := trusted
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check current trust status (bypass stays active if set)
				current := tlsMgr.IsCertificateTrusted()
				if os.Getenv("PM_AUTHROUTER_SKIP_CERT_CHECK") == "1" {
					current = true
				}
				
				if current && !lastTrusted {
					log.Println("Detected certificate trust established; enabling DNS interception...")
					if err := systemMgr.SetupDNSInterception("identity.getpostman.com"); err != nil {
						log.Printf("Failed to setup DNS interception: %v", err)
					} else if !dnsMonitorStarted {
						wg.Add(1)
						go func() {
							defer wg.Done()
							monitorDNSInterception(ctx, systemMgr)
						}()
						dnsMonitorStarted = true
					}
				} else if !current && lastTrusted {
					log.Println("Detected certificate trust revoked; disabling DNS interception...")
					if err := systemMgr.CleanupDNSInterception(); err != nil {
						log.Printf("Warning: Failed to cleanup DNS interception: %v", err)
					}
					if err := systemMgr.CleanupStaleHostsEntries(); err != nil {
						log.Printf("Warning: Failed to cleanup hosts entries: %v", err)
					}
				}
				lastTrusted = current
			}
		}
	}()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Register cleanup handlers
	defer func() {
		log.Println("Performing cleanup...")
		
		// Clean up DNS interception
		if err := systemMgr.CleanupDNSInterception(); err != nil {
			log.Printf("Warning: Failed to cleanup DNS interception: %v", err)
		}
		
		// Remove hosts entries (fallback cleanup)
		if err := systemMgr.CleanupStaleHostsEntries(); err != nil {
			log.Printf("Warning: Failed to cleanup hosts entries: %v", err)
		}

		// Clean up certificates (optional - may want to leave them)
		// tlsMgr.CleanupOldCertificates()
		
		log.Println("Cleanup complete")
	}()

	log.Printf("AuthRouter running on port %d", httpsPort)
	log.Println("Press Ctrl+C to stop")

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutdown signal received, stopping...")

	// Cancel context to stop all goroutines
	cancel()

	// Wait for all goroutines to finish
	wg.Wait()

	log.Println("AuthRouter stopped")
}