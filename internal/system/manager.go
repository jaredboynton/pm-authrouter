package system

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	
	"pm-authrouter/internal/dns"
)

const (
	hostsEntry = "127.0.0.1 identity.getpostman.com"
	windowsHostsPath = `C:\Windows\System32\drivers\etc\hosts`
	unixHostsPath    = "/etc/hosts"
)

// Manager handles system-level operations like hosts file management
type Manager struct{
	dnsInterceptor *dns.Interceptor
}

// NewManager creates a new system manager
func NewManager() *Manager {
	return &Manager{
		dnsInterceptor: nil,
	}
}

// SetupDNSInterception sets up robust DNS interception using multiple fallback methods
func (m *Manager) SetupDNSInterception(targetDomain string) error {
	config := dns.InterceptorConfig{
		TargetDomain:    targetDomain,
		RedirectIP:      "127.0.0.1",
		EnableFallbacks: true,
		LogLevel:        "info",
	}

	m.dnsInterceptor = dns.NewInterceptor(config)
	
	log.Printf("Setting up DNS interception for %s", targetDomain)
	
	if err := m.dnsInterceptor.Start(); err != nil {
		return fmt.Errorf("failed to start DNS interception: %w", err)
	}

	log.Printf("DNS interception active using method: %s", m.dnsInterceptor.GetActiveMethod())
	return nil
}

// CleanupDNSInterception stops and cleans up DNS interception
func (m *Manager) CleanupDNSInterception() error {
	if m.dnsInterceptor == nil {
		return nil
	}

	log.Printf("Cleaning up DNS interception...")
	
	if err := m.dnsInterceptor.Stop(); err != nil {
		return fmt.Errorf("failed to stop DNS interception: %w", err)
	}

	m.dnsInterceptor = nil
	log.Printf("DNS interception cleanup complete")
	return nil
}

// CheckDNSInterception verifies that DNS interception is working correctly
func (m *Manager) CheckDNSInterception() bool {
	if m.dnsInterceptor == nil {
		return false
	}

	return m.dnsInterceptor.IsActive()
}

// GetDNSStatus returns detailed DNS interception status
func (m *Manager) GetDNSStatus() map[string]interface{} {
	if m.dnsInterceptor == nil {
		return map[string]interface{}{
			"active": false,
			"method": "none",
		}
	}

	return m.dnsInterceptor.GetStatus()
}

// getHostsFilePath returns the hosts file path for the current platform
func (m *Manager) getHostsFilePath() string {
	switch runtime.GOOS {
	case "windows":
		return windowsHostsPath
	default:
		return unixHostsPath
	}
}

// CleanupStaleHostsEntries removes any existing hosts entries from previous daemon instances
func (m *Manager) CleanupStaleHostsEntries() error {
	hostsFile := m.getHostsFilePath()
	
	if _, err := os.Stat(hostsFile); os.IsNotExist(err) {
		log.Printf("Warning: Hosts file not found: %s", hostsFile)
		return nil
	}

	// Read current hosts file
	content, err := os.ReadFile(hostsFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	removed := false

	// Remove lines containing our hosts entry
	for _, line := range lines {
		if strings.Contains(line, "127.0.0.1") && strings.Contains(line, "identity.getpostman.com") {
			log.Printf("Removing stale hosts entry: %s", strings.TrimSpace(line))
			removed = true
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}

	// Write back if content changed
	if removed {
		// Create backup
		backupPath := hostsFile + ".backup"
		if err := os.WriteFile(backupPath, content, 0644); err != nil {
			log.Printf("Warning: Failed to create backup: %v", err)
		} else {
			log.Printf("Created hosts file backup: %s", backupPath)
		}

		// Write cleaned content
		cleanedContent := strings.Join(cleanedLines, "\n")
		if err := os.WriteFile(hostsFile, []byte(cleanedContent), 0644); err != nil {
			return fmt.Errorf("failed to write cleaned hosts file: %w", err)
		}

		log.Println("Cleaned up stale hosts entries")
	}

	return nil
}

// SetupHostsFile adds the hosts file entry for identity.getpostman.com
func (m *Manager) SetupHostsFile() error {
	hostsFile := m.getHostsFilePath()

	// Read current hosts file
	content, err := os.ReadFile(hostsFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	// Check if entry already exists
	if strings.Contains(string(content), hostsEntry) {
		log.Println("Hosts file entry already exists")
		return nil
	}

	// Create backup
	backupPath := hostsFile + ".backup"
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		log.Printf("Warning: Failed to create backup: %v", err)
	}

	// Add entry
	newContent := string(content)
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += hostsEntry + "\n"

	if err := os.WriteFile(hostsFile, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	log.Println("Added hosts file entry")
	return nil
}

// CheckHostsEntry verifies that the hosts entry exists and is correct
func (m *Manager) CheckHostsEntry() bool {
	hostsFile := m.getHostsFilePath()

	content, err := os.ReadFile(hostsFile)
	if err != nil {
		return false
	}

	return strings.Contains(string(content), hostsEntry)
}

// RestoreHostsEntry restores the hosts entry if it's missing
func (m *Manager) RestoreHostsEntry() error {
	if m.CheckHostsEntry() {
		return nil
	}

	log.Println("Hosts file entry missing, restoring...")
	return m.SetupHostsFile()
}