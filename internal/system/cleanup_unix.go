//go:build !windows

package system

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// CleanupManager provides centralized cleanup for all Postman AuthRouter components on Unix systems
// Used by: LaunchDaemon shutdown, PKG uninstaller, test framework, manual cleanup
type CleanupManager struct {
	serviceName     string
	certSubject     string
	logPaths        []string
	certPaths       []string
	binaryPaths     []string
	hostsPath       string
	backupPath      string
	launchdPlistPath string
}

// NewCleanupManager creates a new cleanup manager with standard Postman AuthRouter paths for Unix
func NewCleanupManager() *CleanupManager {
	var logPaths, certPaths, binaryPaths []string
	var launchdPlistPath string
	
	if runtime.GOOS == "darwin" {
		// macOS paths
		logPaths = []string{
			"/var/log/postman/pm-authrouter.log",
			"/tmp/pm-authrouter.log",
		}
		certPaths = []string{
			"/usr/local/bin/postman/identity.getpostman.com.crt",
			"/usr/local/bin/postman/identity.getpostman.com.key",
			"/usr/local/bin/postman/ca.crt",
		}
		binaryPaths = []string{
			"/usr/local/bin/postman/pm-authrouter",
		}
		launchdPlistPath = "/Library/LaunchDaemons/com.postman.pm-authrouter.plist"
	} else {
		// Linux paths
		logPaths = []string{
			"/var/log/pm-authrouter.log",
			"/tmp/pm-authrouter.log",
		}
		certPaths = []string{
			"/usr/local/bin/pm-authrouter/identity.getpostman.com.crt",
			"/usr/local/bin/pm-authrouter/identity.getpostman.com.key",
			"/usr/local/bin/pm-authrouter/ca.crt",
		}
		binaryPaths = []string{
			"/usr/local/bin/pm-authrouter",
		}
	}

	return &CleanupManager{
		serviceName:      "com.postman.pm-authrouter",
		certSubject:      "identity.getpostman.com",
		logPaths:         logPaths,
		certPaths:        certPaths,
		binaryPaths:      binaryPaths,
		hostsPath:        "/etc/hosts",
		backupPath:       "/etc/hosts.pm-authrouter-backup",
		launchdPlistPath: launchdPlistPath,
	}
}

// FullCleanup performs complete cleanup of all Postman AuthRouter components on Unix
// This is the single source of truth for cleanup - used everywhere
func (c *CleanupManager) FullCleanup() error {
	log.Println("Starting comprehensive AuthRouter cleanup...")
	
	var errors []string
	
	// 1. Stop and remove Unix service (LaunchDaemon or systemd)
	if err := c.cleanupService(); err != nil {
		errors = append(errors, fmt.Sprintf("Service cleanup: %v", err))
	}
	
	// 2. Clean up all DNS interception methods (hosts file, pfctl, routes)
	if err := c.cleanupDNSMethods(); err != nil {
		errors = append(errors, fmt.Sprintf("DNS cleanup: %v", err))
	}
	
	// 3. Remove certificates from system keychain/certificate stores
	if err := c.cleanupCertificates(); err != nil {
		errors = append(errors, fmt.Sprintf("Certificate cleanup: %v", err))
	}
	
	// 4. Remove certificate files
	if err := c.cleanupCertificateFiles(); err != nil {
		errors = append(errors, fmt.Sprintf("Certificate files cleanup: %v", err))
	}
	
	// 5. Remove log files
	if err := c.cleanupLogFiles(); err != nil {
		errors = append(errors, fmt.Sprintf("Log cleanup: %v", err))
	}
	
	// 6. Remove binary files
	if err := c.cleanupBinaryFiles(); err != nil {
		errors = append(errors, fmt.Sprintf("Binary cleanup: %v", err))
	}
	
	if len(errors) > 0 {
		log.Printf("Cleanup completed with warnings: %s", strings.Join(errors, "; "))
		return fmt.Errorf("cleanup completed with %d warnings", len(errors))
	}
	
	log.Println("AuthRouter cleanup completed successfully")
	return nil
}

// cleanupService stops and removes the Unix service (LaunchDaemon or systemd)
func (c *CleanupManager) cleanupService() error {
	if runtime.GOOS == "darwin" {
		return c.cleanupLaunchDaemon()
	} else {
		return c.cleanupSystemdService()
	}
}

// cleanupLaunchDaemon stops and removes the macOS LaunchDaemon
func (c *CleanupManager) cleanupLaunchDaemon() error {
	log.Printf("Cleaning up macOS LaunchDaemon: %s", c.serviceName)
	
	// Stop service (ignore errors - service might not be running)
	exec.Command("launchctl", "stop", c.serviceName).Run()
	exec.Command("launchctl", "unload", c.launchdPlistPath).Run()
	
	// Remove service plist
	if err := os.Remove(c.launchdPlistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove LaunchDaemon plist: %w", err)
	}
	
	log.Printf("Removed macOS LaunchDaemon: %s", c.serviceName)
	return nil
}

// cleanupSystemdService stops and removes the Linux systemd service
func (c *CleanupManager) cleanupSystemdService() error {
	log.Printf("Cleaning up Linux systemd service: %s", c.serviceName)
	
	// Stop and disable service (ignore errors - service might not exist)
	exec.Command("systemctl", "stop", c.serviceName).Run()
	exec.Command("systemctl", "disable", c.serviceName).Run()
	
	// Remove service file
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", c.serviceName)
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to remove systemd service file: %v", err)
	}
	
	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()
	
	log.Printf("Removed Linux systemd service: %s", c.serviceName)
	return nil
}

// cleanupDNSMethods removes all DNS interception methods
func (c *CleanupManager) cleanupDNSMethods() error {
	log.Println("Cleaning up DNS interception methods...")
	
	var errors []string
	
	// 1. Clean up pfctl redirection (macOS)
	if runtime.GOOS == "darwin" {
		if err := c.cleanupPfctlRedirection(); err != nil {
			errors = append(errors, fmt.Sprintf("pfctl: %v", err))
		}
	}
	
	// 2. Clean up route-based redirection
	if err := c.cleanupRouteRedirection(); err != nil {
		errors = append(errors, fmt.Sprintf("routes: %v", err))
	}
	
	// 3. Clean hosts file (fallback method)
	if err := c.cleanupHostsFile(); err != nil {
		errors = append(errors, fmt.Sprintf("hosts file: %v", err))
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("DNS cleanup warnings: %s", strings.Join(errors, "; "))
	}
	
	return nil
}

// cleanupPfctlRedirection removes pfctl-based DNS redirection (macOS)
func (c *CleanupManager) cleanupPfctlRedirection() error {
	log.Println("Cleaning up pfctl redirection...")
	
	// Remove our rules file
	rulesPath := "/tmp/pm-authrouter.pfctl.rules"
	if err := os.Remove(rulesPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to remove pfctl rules file: %v", err)
	}
	
	// Flush pfctl NAT rules
	exec.Command("pfctl", "-F", "nat").Run()
	
	log.Println("pfctl redirection cleaned up")
	return nil
}

// cleanupRouteRedirection removes route-based DNS redirection
func (c *CleanupManager) cleanupRouteRedirection() error {
	log.Println("Cleaning up route redirection...")
	
	// Get real IP address to remove routes
	cmd := exec.Command("nslookup", c.certSubject, "8.8.8.8")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Warning: Could not resolve real IP for route cleanup: %v", err)
		return nil // Don't fail cleanup if we can't resolve
	}
	
	// Parse IP from nslookup output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Address:") && !strings.HasSuffix(line, "#53") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				realIP := strings.TrimSpace(parts[1])
				// Remove route (ignore errors - route might not exist)
				if runtime.GOOS == "darwin" {
					exec.Command("route", "delete", "-host", realIP).Run()
				} else {
					exec.Command("ip", "route", "del", realIP).Run()
				}
				log.Printf("Removed route: %s -> 127.0.0.1", realIP)
				break
			}
		}
	}
	
	return nil
}

// cleanupHostsFile removes hosts entries and restores backup
func (c *CleanupManager) cleanupHostsFile() error {
	log.Println("Cleaning hosts file...")
	
	// First try to restore from backup if it exists
	if _, err := os.Stat(c.backupPath); err == nil {
		log.Println("Restoring hosts file from backup...")
		if err := os.Rename(c.backupPath, c.hostsPath); err != nil {
			log.Printf("Warning: Failed to restore hosts backup: %v", err)
			// Continue with manual cleanup
		} else {
			log.Println("Hosts file restored from backup")
			return nil
		}
	}
	
	// Manual cleanup - remove entries containing our domain or marker
	content, err := os.ReadFile(c.hostsPath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}
	
	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	removed := 0
	
	for _, line := range lines {
		// Remove lines containing our domain or PostmanAuthRouter marker
		if strings.Contains(line, c.certSubject) || strings.Contains(line, "PostmanAuthRouter") {
			removed++
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}
	
	if removed > 0 {
		cleanedContent := strings.Join(cleanedLines, "\n")
		if err := os.WriteFile(c.hostsPath, []byte(cleanedContent), 0644); err != nil {
			return fmt.Errorf("failed to write cleaned hosts file: %w", err)
		}
		log.Printf("Removed %d entries from hosts file", removed)
	}
	
	return nil
}

// cleanupCertificates removes certificates from system keychain/certificate stores
func (c *CleanupManager) cleanupCertificates() error {
	log.Println("Removing certificates from system keychain/certificate stores...")
	
	if runtime.GOOS == "darwin" {
		return c.cleanupMacOSCertificates()
	} else {
		return c.cleanupLinuxCertificates()
	}
}

// cleanupMacOSCertificates removes certificates from macOS keychain
func (c *CleanupManager) cleanupMacOSCertificates() error {
	// Remove from System keychain
	subjects := []string{c.certSubject, "Postman AuthRouter CA"}
	
	for _, subject := range subjects {
		cmd := exec.Command("security", "delete-certificate", "-c", subject, "/Library/Keychains/System.keychain")
		cmd.Run() // Ignore errors - cert might not exist
	}
	
	log.Println("macOS keychain cleanup completed")
	return nil
}

// cleanupLinuxCertificates removes certificates from Linux certificate stores
func (c *CleanupManager) cleanupLinuxCertificates() error {
	// Remove from common Linux certificate directories
	certDirs := []string{
		"/usr/local/share/ca-certificates",
		"/etc/ssl/certs",
		"/etc/ca-certificates",
	}
	
	for _, certDir := range certDirs {
		certFile := filepath.Join(certDir, "postman-authrouter.crt")
		os.Remove(certFile) // Ignore errors
	}
	
	// Update certificate stores
	exec.Command("update-ca-certificates").Run()
	
	log.Println("Linux certificate store cleanup completed")
	return nil
}

// cleanupCertificateFiles removes certificate files from disk
func (c *CleanupManager) cleanupCertificateFiles() error {
	log.Println("Removing certificate files...")
	
	for _, certPath := range c.certPaths {
		if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Failed to remove %s: %v", certPath, err)
		}
	}
	
	return nil
}

// cleanupLogFiles removes log files
func (c *CleanupManager) cleanupLogFiles() error {
	log.Println("Removing log files...")
	
	for _, logPath := range c.logPaths {
		if err := os.Remove(logPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Failed to remove %s: %v", logPath, err)
		}
	}
	
	// Try to remove log directories if empty
	logDirs := []string{"/var/log/postman"}
	for _, logDir := range logDirs {
		if entries, err := os.ReadDir(logDir); err == nil && len(entries) == 0 {
			os.Remove(logDir) // Ignore errors
		}
	}
	
	return nil
}

// cleanupBinaryFiles removes AuthRouter binary files
func (c *CleanupManager) cleanupBinaryFiles() error {
	log.Println("Removing AuthRouter binary files...")
	
	for _, binaryPath := range c.binaryPaths {
		if err := os.Remove(binaryPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Failed to remove %s: %v", binaryPath, err)
		}
	}
	
	// Remove binary directories if empty
	binaryDirs := []string{"/usr/local/bin/postman"}
	for _, binaryDir := range binaryDirs {
		if entries, err := os.ReadDir(binaryDir); err == nil && len(entries) == 0 {
			os.Remove(binaryDir) // Ignore errors
		}
	}
	
	return nil
}

// GetCleanupSummary returns a summary of what will be cleaned up (for dry-run)
func (c *CleanupManager) GetCleanupSummary() string {
	serviceType := "LaunchDaemon"
	if runtime.GOOS != "darwin" {
		serviceType = "systemd service"
	}
	
	return fmt.Sprintf(`AuthRouter Cleanup Summary (Unix):
	- %s: %s
	- DNS Methods: pfctl, routes, hosts file
	- Certificates: %s (from system keychain/certificate stores)
	- Certificate Files: %d files
	- Log Files: %d files  
	- Binary Files: %d files
	- Hosts File: %s (with backup restoration)`,
		serviceType,
		c.serviceName,
		c.certSubject,
		len(c.certPaths),
		len(c.logPaths),
		len(c.binaryPaths),
		c.hostsPath)
}