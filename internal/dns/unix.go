//go:build !windows

package dns

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// startHostsFile implements hosts file method for macOS
func (i *Interceptor) startHostsFile() error {
	return i.setupMacOSHostsFile()
}

// stopHostsFile cleans up hosts file method for macOS
func (i *Interceptor) stopHostsFile() error {
	return i.cleanupMacOSHostsFile()
}

// startMacOSNetworkExtension implements Network Extension DNS proxy for macOS
func (i *Interceptor) startMacOSNetworkExtension() error {
	log.Printf("Attempting macOS Network Extension DNS interception...")
	
	// Check if we're running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("macOS Network Extension requires root privileges")
	}

	// For enterprise deployment, we'll use pfctl (Packet Filter) which is more
	// accessible than full Network Extension development
	return i.setupPfctlRedirection()
}

// stopMacOSNetworkExtension cleans up Network Extension DNS proxy
func (i *Interceptor) stopMacOSNetworkExtension() error {
	return i.cleanupPfctlRedirection()
}

// setupMacOSHostsFile adds hosts file entry on macOS
func (i *Interceptor) setupMacOSHostsFile() error {
	hostsPath := "/etc/hosts"
	entry := fmt.Sprintf("%s %s", i.config.RedirectIP, i.config.TargetDomain)

	// Read current hosts file
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	// Check if entry already exists
	if strings.Contains(string(content), entry) {
		log.Printf("Hosts file entry already exists")
		return nil
	}

	// Create backup
	backupPath := hostsPath + ".pm-authrouter-backup"
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		log.Printf("Warning: Failed to create hosts file backup: %v", err)
	}

	// Add entry
	newContent := string(content)
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += entry + " # Added by PostmanAuthRouter\n"

	if err := os.WriteFile(hostsPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	// Flush DNS cache on macOS
	if err := i.flushDNSCache(); err != nil {
		log.Printf("Warning: Failed to flush DNS cache: %v", err)
	}

	log.Printf("Added hosts file entry: %s", entry)
	return nil
}

// cleanupMacOSHostsFile removes hosts file entry on macOS
func (i *Interceptor) cleanupMacOSHostsFile() error {
	hostsPath := "/etc/hosts"
	
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	removed := false

	for _, line := range lines {
		// Remove our specific entry
		if strings.Contains(line, i.config.RedirectIP) && 
		   strings.Contains(line, i.config.TargetDomain) &&
		   strings.Contains(line, "PostmanAuthRouter") {
			log.Printf("Removing hosts entry: %s", strings.TrimSpace(line))
			removed = true
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}

	if removed {
		cleanedContent := strings.Join(cleanedLines, "\n")
		if err := os.WriteFile(hostsPath, []byte(cleanedContent), 0644); err != nil {
			return fmt.Errorf("failed to write cleaned hosts file: %w", err)
		}
		
		// Flush DNS cache
		if err := i.flushDNSCache(); err != nil {
			log.Printf("Warning: Failed to flush DNS cache: %v", err)
		}
		
		log.Printf("Cleaned up hosts file entry")
	}

	return nil
}

// setupPfctlRedirection uses pfctl for network-level DNS redirection
func (i *Interceptor) setupPfctlRedirection() error {
	log.Printf("Setting up pfctl-based DNS redirection for %s", i.config.TargetDomain)
	
	// First, resolve the real IP address of the target domain
	realIP, err := i.getRealDomainIPMacOS()
	if err != nil {
		return fmt.Errorf("failed to resolve real IP for %s: %w", i.config.TargetDomain, err)
	}

	log.Printf("Real IP for %s: %s", i.config.TargetDomain, realIP)

	// Create pfctl rules file
	rulesPath := "/tmp/pm-authrouter.pfctl.rules"
	rulesContent := fmt.Sprintf(`
# PostmanAuthRouter DNS redirection rules
rdr pass on lo0 inet proto tcp from any to %s port 443 -> 127.0.0.1 port 443
rdr pass on lo0 inet proto tcp from any to %s port 80 -> 127.0.0.1 port 80
`, realIP, realIP)

	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0644); err != nil {
		return fmt.Errorf("failed to write pfctl rules: %w", err)
	}

	// Load the pfctl rules (use absolute path to pfctl)
	cmd := exec.Command("/sbin/pfctl", "-f", rulesPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("pfctl load failed - Output: %s", string(output))
		if _, lookErr := exec.LookPath("/sbin/pfctl"); lookErr != nil {
			return fmt.Errorf("pfctl not found at /sbin/pfctl - may need to install or fix PATH: %w", err)
		}
		return fmt.Errorf("failed to load pfctl rules (ensure running as root): %w", err)
	}

	// Enable pfctl if not already enabled (use absolute path)
	cmd = exec.Command("/sbin/pfctl", "-e")
	if output, err := cmd.CombinedOutput(); err != nil {
		// pfctl -e fails if already enabled, which is fine
		if !strings.Contains(string(output), "already enabled") {
			log.Printf("pfctl enable output: %s", string(output))
			return fmt.Errorf("failed to enable pfctl: %w", err)
		}
	}

	log.Printf("pfctl DNS redirection configured: %s -> 127.0.0.1", realIP)
	return nil
}

// cleanupPfctlRedirection removes pfctl-based redirection
func (i *Interceptor) cleanupPfctlRedirection() error {
	log.Printf("Cleaning up pfctl-based DNS redirection")
	
	// Remove our rules file
	rulesPath := "/tmp/pm-authrouter.pfctl.rules"
	if err := os.Remove(rulesPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to remove pfctl rules file: %v", err)
	}

	// Flush pfctl rules (this will remove all rules, including ours)
	// Note: This is aggressive but ensures cleanup
	cmd := exec.Command("/sbin/pfctl", "-F", "nat")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("pfctl flush output: %s", string(output))
		log.Printf("Warning: Failed to flush pfctl nat rules: %v", err)
		// Don't return error - we want cleanup to continue
	}

	log.Printf("pfctl DNS redirection cleaned up")
	return nil
}

// getRealDomainIPMacOS resolves the real IP address bypassing local DNS modifications
func (i *Interceptor) getRealDomainIPMacOS() (string, error) {
	// Use external DNS servers to get real IP
	dnsServers := []string{"8.8.8.8", "1.1.1.1"}
	
	for _, dnsServer := range dnsServers {
		cmd := exec.Command("/usr/bin/nslookup", i.config.TargetDomain, dnsServer)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		// Parse nslookup output to extract IP
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Address:") && !strings.HasSuffix(line, "#53") {
				// Extract IP from "Address: x.x.x.x" format
				parts := strings.Split(line, " ")
				if len(parts) >= 2 {
					ip := strings.TrimSpace(parts[1])
					// Validate IP format (simple check)
					if strings.Count(ip, ".") == 3 {
						return ip, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("could not resolve real IP for %s", i.config.TargetDomain)
}

// flushDNSCache flushes the DNS cache on macOS
func (i *Interceptor) flushDNSCache() error {
	// macOS DNS cache flush commands vary by version
	commands := [][]string{
		{"dscacheutil", "-flushcache"},                           // macOS 10.9+
		{"killall", "-HUP", "mDNSResponder"},                    // macOS 10.10+
		{"discoveryutil", "mdnsflushcache"},                     // Some macOS versions
		{"discoveryutil", "udnsflushcaches"},                    // Some macOS versions
	}

	var lastErr error
	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if err := cmd.Run(); err != nil {
			lastErr = err
			continue
		}
		
		log.Printf("DNS cache flushed using: %v", cmdArgs)
		return nil
	}

	return fmt.Errorf("failed to flush DNS cache, last error: %w", lastErr)
}

// setupRouteRedirection uses route command for IP-level redirection
func (i *Interceptor) setupRouteRedirection() error {
	log.Printf("Setting up route-based DNS redirection...")
	
	realIP, err := i.getRealDomainIPMacOS()
	if err != nil {
		return fmt.Errorf("failed to resolve real IP: %w", err)
	}

	// Add route that redirects the real IP to localhost
	cmd := exec.Command("/sbin/route", "add", "-host", realIP, "127.0.0.1")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Route command output: %s", string(output))
		return fmt.Errorf("failed to add route: %w", err)
	}

	log.Printf("Added route: %s -> 127.0.0.1", realIP)
	return nil
}

// cleanupRouteRedirection removes route-based redirection
func (i *Interceptor) cleanupRouteRedirection() error {
	log.Printf("Cleaning up route-based DNS redirection...")
	
	realIP, err := i.getRealDomainIPMacOS()
	if err != nil {
		log.Printf("Warning: Could not resolve real IP for cleanup: %v", err)
		return nil
	}

	// Remove the route
	cmd := exec.Command("/sbin/route", "delete", "-host", realIP)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Route delete output: %s", string(output))
		log.Printf("Warning: Failed to delete route: %v", err)
		// Don't return error - route might not exist
	}

	log.Printf("Removed route: %s -> 127.0.0.1", realIP)
	return nil
}

// checkSystemIntegrityProtection checks if SIP is enabled (affects some operations)
func checkSystemIntegrityProtection() bool {
	cmd := exec.Command("csrutil", "status")
	output, err := cmd.Output()
	if err != nil {
		return true // Assume enabled if we can't check
	}

	return !strings.Contains(string(output), "disabled")
}

// getMacOSVersion returns the macOS version for compatibility checks
func getMacOSVersion() (int, int) {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return 10, 15 // Default to Catalina
	}

	version := strings.TrimSpace(string(output))
	parts := strings.Split(version, ".")
	
	if len(parts) >= 2 {
		major := 10
		minor := 15
		
		if len(parts) >= 1 && parts[0] == "11" {
			major = 11
			minor = 0
		} else if len(parts) >= 1 && parts[0] == "12" {
			major = 12
			minor = 0
		} else if len(parts) >= 2 {
			// Parse 10.x format
			switch parts[1] {
			case "15":
				minor = 15 // Catalina
			case "16":
				minor = 16 // Big Sur (also appears as 11.x)
			default:
				minor = 15
			}
		}
		
		return major, minor
	}

	return 10, 15
}

// isRunningAsRoot checks if the process is running with root privileges
func isRunningAsRoot() bool {
	return os.Geteuid() == 0
}

// getUserID gets the real user ID (in case of sudo)
func getUserID() (int, error) {
	if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
		// Running under sudo, get real user
		var uid int
		if _, err := fmt.Sscanf(sudoUID, "%d", &uid); err != nil {
			return 0, err
		}
		return uid, nil
	}
	
	return syscall.Getuid(), nil
}

// Stub implementations for Windows methods (not available on macOS)
func (i *Interceptor) startWindowsWFP() error {
	return fmt.Errorf("Windows WFP not available on macOS")
}

func (i *Interceptor) stopWindowsWFP() error {
	return nil
}

func (i *Interceptor) startAPIHooking() error {
	return fmt.Errorf("Windows API hooking not available on macOS")
}

func (i *Interceptor) stopAPIHooking() error {
	return nil
}

func (i *Interceptor) startRegistryOverride() error {
	return fmt.Errorf("Windows Registry override not available on macOS")
}

func (i *Interceptor) stopRegistryOverride() error {
	return nil
}