//go:build windows

package system

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CleanupManager provides centralized cleanup for all Postman AuthRouter components
// Used by: Windows service shutdown, MSI uninstaller, test framework, manual cleanup
type CleanupManager struct {
	serviceName   string
	certSubject   string
	logPaths      []string
	certPaths     []string
	binaryPaths   []string
	hostsPath     string
	backupPath    string
}

// NewCleanupManager creates a new cleanup manager with standard Postman AuthRouter paths
func NewCleanupManager() *CleanupManager {
	return &CleanupManager{
		serviceName: "PostmanAuthRouter",
		certSubject: "identity.getpostman.com",
		logPaths: []string{
			`C:\ProgramData\Postman\pm-authrouter.log`,
			`C:\ProgramData\Postman\saml-enforcer.log`, // Legacy name
			`C:\temp\pm-authrouter.log`,
		},
		certPaths: []string{
			`C:\Program Files\Postman\Postman Enterprise\ca.crt`,
			`C:\Program Files\Postman\Postman Enterprise\server.crt`,
			`C:\Program Files\Postman\Postman Enterprise\server.key`,
		},
		binaryPaths: []string{
			`C:\Program Files\Postman\Postman Enterprise\pm-authrouter.exe`,
		},
		hostsPath:  `C:\Windows\System32\drivers\etc\hosts`,
		backupPath: `C:\Windows\System32\drivers\etc\hosts.pm-authrouter-backup`,
	}
}

// FullCleanup performs complete cleanup of all Postman AuthRouter components
// This is the single source of truth for cleanup - used everywhere
func (c *CleanupManager) FullCleanup() error {
	log.Println("Starting comprehensive AuthRouter cleanup...")
	
	var errors []string
	
	// 1. Stop and remove Windows service
	if err := c.cleanupService(); err != nil {
		errors = append(errors, fmt.Sprintf("Service cleanup: %v", err))
	}
	
	// 2. Clean up all DNS interception methods (primary, secondary, fallback)
	if err := c.cleanupDNSMethods(); err != nil {
		errors = append(errors, fmt.Sprintf("DNS cleanup: %v", err))
	}
	
	// 3. Remove certificates from Windows certificate store
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

// cleanupService stops and removes the Windows service
func (c *CleanupManager) cleanupService() error {
	log.Printf("Cleaning up Windows service: %s", c.serviceName)
	
	// Stop service (ignore errors - service might not be running)
	exec.Command("net", "stop", c.serviceName).Run()
	exec.Command("sc", "stop", c.serviceName).Run()
	
	// Wait a moment for service to stop
	exec.Command("timeout", "/t", "3", "/nobreak").Run()
	
	// Remove service
	cmd := exec.Command("sc", "delete", c.serviceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Only log as warning if service doesn't exist
		if strings.Contains(string(output), "does not exist") {
			log.Printf("Service %s was not installed", c.serviceName)
			return nil
		}
		return fmt.Errorf("failed to remove service: %v, output: %s", err, string(output))
	}
	
	log.Printf("Removed Windows service: %s", c.serviceName)
	return nil
}

// cleanupDNSMethods removes all DNS interception methods
func (c *CleanupManager) cleanupDNSMethods() error {
	log.Println("Cleaning up DNS interception methods...")
	
	var errors []string
	
	// 1. Clean up netsh routing (primary method)
	if err := c.cleanupNetshRouting(); err != nil {
		errors = append(errors, fmt.Sprintf("netsh routing: %v", err))
	}
	
	// 2. Clean up DNS registry override (secondary method)  
	if err := c.cleanupDNSRegistryOverride(); err != nil {
		errors = append(errors, fmt.Sprintf("DNS registry: %v", err))
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

// cleanupNetshRouting removes network routes (primary DNS method)
func (c *CleanupManager) cleanupNetshRouting() error {
	log.Println("Cleaning up network routes...")
	
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
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				realIP := strings.TrimSpace(parts[1])
				// Remove route (ignore errors - route might not exist)
				exec.Command("route", "DELETE", realIP, "127.0.0.1").Run()
				log.Printf("Removed route: %s -> 127.0.0.1", realIP)
				break
			}
		}
	}
	
	return nil
}

// cleanupDNSRegistryOverride restores DNS settings (secondary method)
func (c *CleanupManager) cleanupDNSRegistryOverride() error {
	log.Println("Restoring DNS settings...")
	
	script := `
		$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true'
		foreach ($adapter in $adapters) {
			$currentDNS = $adapter.DNSServerSearchOrder
			if ($currentDNS -and $currentDNS[0] -eq '127.0.0.1') {
				$restoredDNS = $currentDNS[1..($currentDNS.Length-1)]
				if ($restoredDNS) {
					$adapter.SetDNSServerSearchOrder($restoredDNS)
					Write-Host "Restored DNS for adapter:" $adapter.Description
				}
			}
		}
	`
	
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-Command", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: DNS restoration output: %s", string(output))
		return fmt.Errorf("failed to restore DNS settings: %v", err)
	}
	
	return nil
}

// cleanupHostsFile removes hosts entries and restores backup (fallback method)
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

// cleanupCertificates removes certificates from Windows certificate store
func (c *CleanupManager) cleanupCertificates() error {
	log.Println("Removing certificates from Windows certificate store...")
	
	// Remove from different certificate stores
	stores := []string{"Root", "TrustedPublisher"}
	subjects := []string{c.certSubject, "Postman AuthRouter CA"}
	
	for _, store := range stores {
		for _, subject := range subjects {
			cmd := exec.Command("certutil", "-delstore", store, subject)
			cmd.Run() // Ignore errors - cert might not exist
		}
	}
	
	log.Println("Certificate store cleanup completed")
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
	
	// Try to remove log directory if empty
	logDir := filepath.Dir(c.logPaths[0])
	if entries, err := os.ReadDir(logDir); err == nil && len(entries) == 0 {
		os.Remove(logDir) // Ignore errors
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
	
	return nil
}

// GetCleanupSummary returns a summary of what will be cleaned up (for dry-run)
func (c *CleanupManager) GetCleanupSummary() string {
	return fmt.Sprintf(`AuthRouter Cleanup Summary:
	- Windows Service: %s
	- DNS Methods: Netsh routing, DNS registry override, hosts file
	- Certificates: %s (from Windows certificate store)
	- Certificate Files: %d files
	- Log Files: %d files  
	- Binary Files: %d files
	- Hosts File: %s (with backup restoration)`,
		c.serviceName,
		c.certSubject,
		len(c.certPaths),
		len(c.logPaths),
		len(c.binaryPaths),
		c.hostsPath)
}