//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"pm-authrouter/internal/config"
	"pm-authrouter/internal/proxy"
	"pm-authrouter/internal/system"
	tlsmgr "pm-authrouter/internal/tls"
)

const serviceName = "PostmanAuthRouter"
const serviceDisplayName = "Postman AuthRouter"
const serviceDescription = "Enterprise authentication router daemon for Postman Desktop applications"

type authrouter struct {
	elog debug.Log
}

// Execute implements the Windows service interface
func (m *authrouter) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	// Install panic handler FIRST
	defer func() {
		if r := recover(); r != nil {
			m.elog.Error(1, fmt.Sprintf("Service panic: %v", r))
			emergencyDNSCleanup()  // ALWAYS clean DNS on panic
			logEventToWindows("ERROR", "Service crashed - DNS cleaned up automatically")
		}
	}()
	
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Set up context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the daemon in a goroutine
	daemonErr := make(chan error, 1)
	go func() {
		daemonErr <- runDaemon(ctx, m.elog)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				m.elog.Info(1, "Service stop requested")
				break loop
			default:
				m.elog.Error(1, fmt.Sprintf("Unexpected control request #%d", c))
			}
		case err := <-daemonErr:
			if err != nil {
				m.elog.Error(1, fmt.Sprintf("Daemon error: %v", err))
			}
			break loop
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	
	// Cancel context to stop daemon
	cancel()
	
	// Wait a bit for cleanup
	time.Sleep(2 * time.Second)
	
	return false, 0
}

// runDaemon runs the main daemon logic (shared with non-service mode)
func runDaemon(ctx context.Context, elog debug.Log) error {
	// Set up logging to file
	logFilePath := "C:\\ProgramData\\Postman\\pm-authrouter.log"
	
	// Ensure log directory exists
	logDir := filepath.Dir(logFilePath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("Failed to create log directory: %v", err))
		}
		// Continue anyway - will log to stderr
	}
	
	logFile, err := os.OpenFile(logFilePath,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		log.SetOutput(logFile)
		// Don't close the file here - it needs to stay open for logging
		// The file will be closed when the process exits
	} else {
		// Log the error but continue with stderr logging
		if elog != nil {
			elog.Warning(1, fmt.Sprintf("Failed to open log file %s: %v, using stderr", logFilePath, err))
		}
	}

	log.SetPrefix("[pm-authrouter] ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if elog != nil {
		elog.Info(1, "Starting Postman AuthRouter daemon")
	}
	log.Println("Starting Postman AuthRouter daemon...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("Failed to load configuration: %v", err))
		}
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	log.Printf("Loaded configuration for team: %s", cfg.TeamName)
	
	// Create required directories
	certDir := filepath.Dir(cfg.SSLCert)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("Failed to create certificate directory %s: %v", certDir, err))
		}
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Check for and terminate any existing daemon instances
	processMgr := system.NewProcessManager()
	existingPIDs, err := processMgr.FindRunningDaemons(httpsPort)
	if err != nil {
		log.Printf("Warning: Error checking for existing daemons: %v", err)
	} else if len(existingPIDs) > 0 {
		log.Printf("Found %d existing daemon process(es). Terminating...", len(existingPIDs))
		if err := processMgr.TerminateExistingDaemons(existingPIDs); err != nil {
			log.Printf("Warning: Error terminating existing daemons: %v", err)
		}
	}

	// Set up system integration
	systemMgr := system.NewManager()

	// Clean up any stale hosts entries
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

	// Generate/validate certificates
	certPath, keyPath, err := tlsMgr.EnsureValidCertificates()
	if err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("Certificate generation failed: %v", err))
		}
		log.Printf("Certificate generation failed: %v", err)
		return fmt.Errorf("failed to set up SSL certificates: %w", err)
	}

	// Create HTTPS proxy server
	proxyServer, err := proxy.NewServer(cfg, certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed to create proxy server: %w", err)
	}

	var wg sync.WaitGroup

	// Start the proxy server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := proxyServer.Start(ctx); err != nil {
			log.Printf("Proxy server error: %v", err)
		}
	}()

	// Wait for server to start and verify health with retries
	if err := waitForServerReady(cfg, 30*time.Second); err != nil {
		return fmt.Errorf("server failed to become ready: %w", err)
	}

	// Setup DNS interception with fallback methods
	if err := systemMgr.SetupDNSInterception("identity.getpostman.com"); err != nil {
		return fmt.Errorf("failed to setup DNS interception: %w", err)
	}

	// Start DNS interception monitoring
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorDNSInterception(ctx, systemMgr)
	}()



	// Register cleanup
	defer func() {
		log.Println("Performing cleanup...")
		
		// Clean up DNS interception
		if err := systemMgr.CleanupDNSInterception(); err != nil {
			log.Printf("Warning: Failed to cleanup DNS interception: %v", err)
		}
		
		// Clean up hosts entries (fallback cleanup)
		if err := systemMgr.CleanupStaleHostsEntries(); err != nil {
			log.Printf("Warning: Failed to cleanup hosts entries: %v", err)
		}
		
		log.Println("Cleanup complete")
	}()

	if elog != nil {
		elog.Info(1, fmt.Sprintf("AuthRouter running on port %d", httpsPort))
	}
	log.Printf("AuthRouter running on port %d", httpsPort)

	// Wait for context cancellation
	<-ctx.Done()
	
	if elog != nil {
		elog.Info(1, "Shutting down daemon")
	}
	log.Println("Shutting down daemon...")

	// Wait for goroutines
	wg.Wait()

	return nil
}

// runService runs as a Windows service
func runService(name string, isDebug bool) {
	var elog debug.Log
	if isDebug {
		elog = debug.New(name)
	} else {
		var err error
		elog, err = eventlog.Open(name)
		if err != nil {
			return
		}
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s service", name))
	
	run := svc.Run
	if isDebug {
		run = debug.Run
	}
	
	err := run(name, &authrouter{elog: elog})
	if err != nil {
		elog.Error(1, fmt.Sprintf("Service failed: %v", err))
		return
	}
	elog.Info(1, fmt.Sprintf("%s service stopped", name))
}

// installService installs the Windows service
func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	// Get the team and saml-url from command-line flags
	args := []string{"service"}
	if teamFlag := flag.Lookup("team"); teamFlag != nil && teamFlag.Value.String() != "" {
		args = append(args, "--team", teamFlag.Value.String())
	}
	if samlFlag := flag.Lookup("saml-url"); samlFlag != nil && samlFlag.Value.String() != "" {
		args = append(args, "--saml-url", samlFlag.Value.String())
	}
	
	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName:  serviceDisplayName,
		Description:  serviceDescription,
		StartType:    mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return err
	}
	defer s.Close()

	// Configure recovery actions
	err = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
	}, 0)
	if err != nil {
		log.Printf("Warning: Failed to set recovery actions: %v", err)
	}

	fmt.Printf("Service %s installed successfully\n", serviceName)
	return nil
}

// removeService removes the Windows service
func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return err
	}

	fmt.Printf("Service %s removed successfully\n", serviceName)
	return nil
}

// startService starts the Windows service
func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer s.Close()

	err = s.Start("service")
	if err != nil {
		return fmt.Errorf("could not start service: %v", err)
	}

	fmt.Printf("Service %s started successfully\n", serviceName)
	return nil
}

// stopService stops the Windows service
func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("could not send stop control: %v", err)
	}

	timeout := time.Now().Add(10 * time.Second)
	for status.State != svc.Stopped {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("timeout waiting for service to stop")
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("could not retrieve service status: %v", err)
		}
	}

	fmt.Printf("Service %s stopped successfully\n", serviceName)
	return nil
}

// emergencyDNSCleanup performs direct hosts file cleanup without dependencies
func emergencyDNSCleanup() {
	// Simple, direct cleanup - no dependencies
	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		// Can't read hosts file, nothing to clean
		return
	}
	
	lines := strings.Split(string(content), "\n")
	var cleaned []string
	for _, line := range lines {
		// Remove any PostmanAuthRouter or identity.getpostman.com entries
		if !strings.Contains(line, "PostmanAuthRouter") &&
		   !strings.Contains(line, "identity.getpostman.com") {
			cleaned = append(cleaned, line)
		}
	}
	
	// Write back cleaned hosts file
	os.WriteFile(hostsPath, []byte(strings.Join(cleaned, "\n")), 0644)
}

// logEventToWindows logs to Windows Event Log
func logEventToWindows(eventType string, message string) {
	// Log to Windows Event Log so IT can see crashes
	cmd := exec.Command("eventcreate",
		"/T", eventType,
		"/ID", "1001",
		"/L", "APPLICATION",
		"/SO", "PostmanAuthRouter",
		"/D", message)
	cmd.Run()
}