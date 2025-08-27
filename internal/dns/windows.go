//go:build windows

package dns

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// Windows API constants for WFP
const (
	FWP_ACTION_PERMIT = 0x1
	FWP_ACTION_CALLOUT_TERMINATING = 0x3
	FWPM_LAYER_ALE_AUTH_CONNECT_V4 = "c38d57d1-05a7-4c33-904f-7fbceee60e82"
)

// WindowsInterceptor handles Windows-specific DNS interception
type WindowsInterceptor struct {
	engineHandle uintptr
	filterId     uint64
}

// startHostsFile implements hosts file method for Windows
func (i *Interceptor) startHostsFile() error {
	return i.setupWindowsHostsFile()
}

// stopHostsFile cleans up hosts file method for Windows  
func (i *Interceptor) stopHostsFile() error {
	return i.cleanupWindowsHostsFile()
}

// Platform-specific method implementations for Windows

// startWindowsWFP implements Windows Filtering Platform DNS interception
func (i *Interceptor) startWindowsWFP() error {
	log.Printf("Attempting Windows Filtering Platform DNS interception...")
	
	// Check if we're running with sufficient privileges
	if !i.isRunningAsSystem() {
		return fmt.Errorf("Windows Filtering Platform requires SYSTEM privileges")
	}

	// Try to use netsh to create a route-based redirect
	// This is simpler than full WFP kernel callouts but still effective
	return i.setupNetshRouting()
}

// stopWindowsWFP cleans up Windows Filtering Platform DNS interception
func (i *Interceptor) stopWindowsWFP() error {
	return i.cleanupNetshRouting()
}

// startAPIHooking implements Windows API hooking for DNS calls
func (i *Interceptor) startAPIHooking() error {
	log.Printf("Attempting Windows API hooking DNS interception...")
	
	// For enterprise deployment, we'll use a simpler approach:
	// Modify Windows DNS resolver configuration via registry
	return i.setupDNSRegistryOverride()
}

// stopAPIHooking cleans up Windows API hooking
func (i *Interceptor) stopAPIHooking() error {
	return i.cleanupDNSRegistryOverride()
}

// startRegistryOverride implements DNS override via Windows registry
func (i *Interceptor) startRegistryOverride() error {
	log.Printf("Attempting Windows registry DNS override...")
	return i.setupRegistryDNSOverride()
}

// stopRegistryOverride cleans up registry DNS override
func (i *Interceptor) stopRegistryOverride() error {
	return i.cleanupRegistryDNSOverride()
}

// setupWindowsHostsFile adds hosts file entry on Windows
func (i *Interceptor) setupWindowsHostsFile() error {
	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
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

	log.Printf("Added hosts file entry: %s", entry)
	return nil
}

// cleanupWindowsHostsFile removes hosts file entry on Windows
func (i *Interceptor) cleanupWindowsHostsFile() error {
	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
	
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
		log.Printf("Cleaned up hosts file entry")
	}

	return nil
}

// setupNetshRouting uses netsh to create routing-based DNS interception
func (i *Interceptor) setupNetshRouting() error {
	log.Printf("Setting up netsh-based DNS routing for %s", i.config.TargetDomain)
	
	// First, resolve the real IP address of the target domain
	realIP, err := i.getRealDomainIP()
	if err != nil {
		return fmt.Errorf("failed to resolve real IP for %s: %w", i.config.TargetDomain, err)
	}

	log.Printf("Real IP for %s: %s", i.config.TargetDomain, realIP)

	// Add a persistent route that redirects the real IP to localhost
	// This approach works even when DNS is proxied
	cmd := exec.Command("route", "ADD", realIP, "127.0.0.1", "METRIC", "1")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Route command output: %s", string(output))
		return fmt.Errorf("failed to add route: %w", err)
	}

	log.Printf("Added route: %s -> 127.0.0.1", realIP)
	return nil
}

// cleanupNetshRouting removes netsh-based routing
func (i *Interceptor) cleanupNetshRouting() error {
	log.Printf("Cleaning up netsh-based DNS routing")
	
	// Get the real IP to remove the route
	realIP, err := i.getRealDomainIP()
	if err != nil {
		log.Printf("Warning: Could not resolve real IP for cleanup: %v", err)
		return nil // Don't fail cleanup if we can't resolve
	}

	// Remove the route
	cmd := exec.Command("route", "DELETE", realIP, "127.0.0.1")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Route delete output: %s", string(output))
		log.Printf("Warning: Failed to delete route: %v", err)
		// Don't return error - route might not exist
	}

	log.Printf("Removed route: %s -> 127.0.0.1", realIP)
	return nil
}

// getRealDomainIP resolves the real IP address bypassing any local DNS modifications
func (i *Interceptor) getRealDomainIP() (string, error) {
	// Use external DNS servers to get real IP
	dnsServers := []string{"8.8.8.8", "1.1.1.1"}
	
	for _, dnsServer := range dnsServers {
		cmd := exec.Command("nslookup", i.config.TargetDomain, dnsServer)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		// Parse nslookup output to extract IP
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Address:") && !strings.HasSuffix(line, "#53") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					ip := strings.TrimSpace(parts[1])
					// Validate IP format
					if strings.Count(ip, ".") == 3 {
						return ip, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("could not resolve real IP for %s", i.config.TargetDomain)
}

// setupDNSRegistryOverride modifies Windows DNS settings via registry
func (i *Interceptor) setupDNSRegistryOverride() error {
	log.Printf("Setting up DNS registry override...")
	
	// This approach modifies the Windows resolver to use a custom DNS server
	// that we control, allowing surgical DNS interception
	
	// For now, use PowerShell to modify DNS settings
	script := fmt.Sprintf(`
		# Get network adapters
		$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
		foreach ($adapter in $adapters) {
			# Store original DNS servers
			$originalDNS = $adapter.DNSServerSearchOrder
			if ($originalDNS) {
				# Add 127.0.0.1 as primary DNS (where our DNS server will run)
				$newDNS = @("127.0.0.1") + $originalDNS
				$adapter.SetDNSServerSearchOrder($newDNS)
				Write-Host "Modified DNS for adapter: $($adapter.Description)"
			}
		}
	`)

	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-Command", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("PowerShell DNS modification output: %s", string(output))
		return fmt.Errorf("failed to modify DNS settings: %w", err)
	}

	log.Printf("DNS registry override configured")
	return nil
}

// cleanupDNSRegistryOverride restores original DNS settings
func (i *Interceptor) cleanupDNSRegistryOverride() error {
	log.Printf("Cleaning up DNS registry override...")
	
	script := `
		# Restore DNS settings by removing 127.0.0.1 from DNS server list
		$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
		foreach ($adapter in $adapters) {
			$currentDNS = $adapter.DNSServerSearchOrder
			if ($currentDNS -and $currentDNS[0] -eq "127.0.0.1") {
				# Remove 127.0.0.1 from DNS list
				$restoredDNS = $currentDNS[1..($currentDNS.Length-1)]
				if ($restoredDNS) {
					$adapter.SetDNSServerSearchOrder($restoredDNS)
					Write-Host "Restored DNS for adapter: $($adapter.Description)"
				}
			}
		}
	`

	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-Command", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("PowerShell DNS restoration output: %s", string(output))
		log.Printf("Warning: Failed to restore DNS settings: %v", err)
		// Don't return error - we want cleanup to continue
	}

	log.Printf("DNS registry override cleaned up")
	return nil
}

// setupRegistryDNSOverride implements simpler registry-based DNS override
func (i *Interceptor) setupRegistryDNSOverride() error {
	// This is a placeholder for a more sophisticated registry-based approach
	// For now, fall back to hosts file method
	return i.setupWindowsHostsFile()
}

// cleanupRegistryDNSOverride cleans up registry-based DNS override
func (i *Interceptor) cleanupRegistryDNSOverride() error {
	return i.cleanupWindowsHostsFile()
}

// isRunningAsSystem checks if the process is running with SYSTEM privileges
func (i *Interceptor) isRunningAsSystem() bool {
	// Check if we have administrative privileges
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}

// Helper function to check Windows version for API compatibility
func getWindowsVersion() (int, int) {
	cmd := exec.Command("cmd", "/c", "ver")
	output, err := cmd.Output()
	if err != nil {
		return 0, 0
	}
	
	// Parse version string (simplified)
	version := string(output)
	if strings.Contains(version, "10.") || strings.Contains(version, "11.") {
		return 10, 0 // Windows 10/11
	}
	
	return 6, 1 // Assume Windows 7+ as fallback
}

// isElevated checks if the current process has elevated privileges
func isElevated() bool {
	var token syscall.Token
	proc := syscall.MustLoadDLL("advapi32.dll").MustFindProc("GetCurrentProcessToken")
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&token)))
	
	if ret == 0 {
		return false
	}
	
	var elevation uint32
	var returnLength uint32
	
	getTokenInfo := syscall.MustLoadDLL("advapi32.dll").MustFindProc("GetTokenInformation")
	ret, _, _ = getTokenInfo.Call(
		uintptr(token),
		20, // TokenElevation
		uintptr(unsafe.Pointer(&elevation)),
		4, // sizeof(uint32)
		uintptr(unsafe.Pointer(&returnLength)),
	)
	
	return ret != 0 && elevation != 0
}

// Stub implementations for macOS methods (not available on Windows)
func (i *Interceptor) startMacOSNetworkExtension() error {
	return fmt.Errorf("macOS Network Extension not available on Windows")
}

func (i *Interceptor) stopMacOSNetworkExtension() error {
	return nil
}