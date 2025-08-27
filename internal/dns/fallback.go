package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// FallbackStrategy handles DNS interception with multiple fallback methods
type FallbackStrategy struct {
	interceptor *Interceptor
	methods     []InterceptionMethod
	current     int
	maxRetries  int
}

// NewFallbackStrategy creates a new fallback strategy
func NewFallbackStrategy(interceptor *Interceptor) *FallbackStrategy {
	return &FallbackStrategy{
		interceptor: interceptor,
		methods:     interceptor.methods,
		current:     -1,
		maxRetries:  3,
	}
}

// TryNextMethod attempts the next available DNS interception method
func (f *FallbackStrategy) TryNextMethod() error {
	if f.current >= len(f.methods)-1 {
		return fmt.Errorf("all DNS interception methods exhausted")
	}

	f.current++
	method := f.methods[f.current]
	
	log.Printf("Trying DNS interception method %d/%d: %s", 
		f.current+1, len(f.methods), f.interceptor.methodName(method))

	return f.interceptor.startMethod(method)
}

// GetCurrentMethod returns the currently active method
func (f *FallbackStrategy) GetCurrentMethod() InterceptionMethod {
	if f.current < 0 || f.current >= len(f.methods) {
		return -1
	}
	return f.methods[f.current]
}

// HasNextMethod returns whether there are more methods to try
func (f *FallbackStrategy) HasNextMethod() bool {
	return f.current < len(f.methods)-1
}

// Reset resets the fallback strategy to try all methods again
func (f *FallbackStrategy) Reset() {
	f.current = -1
}

// EnvironmentAnalyzer analyzes the current environment to recommend optimal DNS methods
type EnvironmentAnalyzer struct {
	config InterceptorConfig
}

// NewEnvironmentAnalyzer creates a new environment analyzer
func NewEnvironmentAnalyzer(config InterceptorConfig) *EnvironmentAnalyzer {
	return &EnvironmentAnalyzer{config: config}
}

// AnalyzeEnvironment analyzes the current environment and returns recommended methods
func (e *EnvironmentAnalyzer) AnalyzeEnvironment() (*EnvironmentInfo, error) {
	info := &EnvironmentInfo{
		Platform:         runtime.GOOS,
		IsVirtualized:    false,
		VirtualTech:      "",
		DNSProxyDetected: false,
		HostsFileWorks:   false,
		Capabilities:     make(map[string]bool),
	}

	// Detect virtualization
	if err := e.detectVirtualization(info); err != nil {
		log.Printf("Warning: Virtualization detection failed: %v", err)
	}

	// Test hosts file effectiveness
	if err := e.testHostsFile(info); err != nil {
		log.Printf("Warning: Hosts file test failed: %v", err)
	}

	// Check DNS proxy
	if err := e.detectDNSProxy(info); err != nil {
		log.Printf("Warning: DNS proxy detection failed: %v", err)
	}

	// Check platform capabilities
	e.checkCapabilities(info)

	log.Printf("Environment analysis complete: virtualized=%v, dns_proxy=%v, hosts_works=%v", 
		info.IsVirtualized, info.DNSProxyDetected, info.HostsFileWorks)

	return info, nil
}

// EnvironmentInfo contains information about the current environment
type EnvironmentInfo struct {
	Platform         string
	IsVirtualized    bool
	VirtualTech      string // "Parallels", "VMware", "Hyper-V", etc.
	DNSProxyDetected bool
	HostsFileWorks   bool
	Capabilities     map[string]bool
}

// GetRecommendedMethods returns DNS methods ranked by likelihood of success
func (e *EnvironmentAnalyzer) GetRecommendedMethods(info *EnvironmentInfo) []InterceptionMethod {
	var methods []InterceptionMethod

	if info.HostsFileWorks && !info.DNSProxyDetected {
		// Hosts file is working and no DNS proxy detected
		methods = append(methods, HostsFile)
	}

	switch info.Platform {
	case "windows":
		if info.IsVirtualized || info.DNSProxyDetected {
			// In virtualized environments or with DNS proxies, use advanced methods first
			if info.Capabilities["wfp"] {
				methods = append(methods, WindowsWFP)
			}
			if info.Capabilities["api_hooking"] {
				methods = append(methods, APIHooking)
			}
			methods = append(methods, RegistryOverride)
		}
		
		// Always include hosts file as fallback if not already added
		if !info.HostsFileWorks {
			methods = append(methods, HostsFile)
		}

	case "darwin":
		if info.IsVirtualized || info.DNSProxyDetected {
			// In virtualized environments, try advanced methods first
			if info.Capabilities["pfctl"] {
				methods = append(methods, MacOSNetworkExtension)
			}
		}
		
		// Always include hosts file as fallback if not already added  
		if !info.HostsFileWorks {
			methods = append(methods, HostsFile)
		}
	}

	return methods
}

// detectVirtualization attempts to detect if running in a virtualized environment
func (e *EnvironmentAnalyzer) detectVirtualization(info *EnvironmentInfo) error {
	switch runtime.GOOS {
	case "windows":
		return e.detectVirtualizationWindows(info)
	case "darwin":
		return e.detectVirtualizationMacOS(info)
	default:
		return nil
	}
}

// detectVirtualizationWindows detects virtualization on Windows
func (e *EnvironmentAnalyzer) detectVirtualizationWindows(info *EnvironmentInfo) error {
	// Check Windows Management Instrumentation for virtualization
	checks := []struct {
		command string
		args    []string
		keyword string
		tech    string
	}{
		{"wmic", []string{"computersystem", "get", "manufacturer"}, "Parallels", "Parallels"},
		{"wmic", []string{"computersystem", "get", "manufacturer"}, "VMware", "VMware"},
		{"wmic", []string{"computersystem", "get", "manufacturer"}, "Microsoft Corporation", "Hyper-V"},
		{"systeminfo", []string{}, "Virtual Machine", "Generic"},
	}

	for _, check := range checks {
		if output, err := runCommand(check.command, check.args...); err == nil {
			if strings.Contains(strings.ToLower(string(output)), strings.ToLower(check.keyword)) {
				info.IsVirtualized = true
				info.VirtualTech = check.tech
				log.Printf("Detected virtualization: %s", check.tech)
				return nil
			}
		}
	}

	return nil
}

// detectVirtualizationMacOS detects virtualization on macOS
func (e *EnvironmentAnalyzer) detectVirtualizationMacOS(info *EnvironmentInfo) error {
	// Check system profiler for virtualization indicators
	if output, err := runCommand("system_profiler", "SPHardwareDataType"); err == nil {
		outputStr := strings.ToLower(string(output))
		
		if strings.Contains(outputStr, "parallels") {
			info.IsVirtualized = true
			info.VirtualTech = "Parallels"
		} else if strings.Contains(outputStr, "vmware") {
			info.IsVirtualized = true
			info.VirtualTech = "VMware"
		} else if strings.Contains(outputStr, "virtualbox") {
			info.IsVirtualized = true
			info.VirtualTech = "VirtualBox"
		}

		if info.IsVirtualized {
			log.Printf("Detected virtualization: %s", info.VirtualTech)
		}
	}

	return nil
}

// testHostsFile tests whether the hosts file is effective for DNS resolution
func (e *EnvironmentAnalyzer) testHostsFile(info *EnvironmentInfo) error {
	// Test by attempting to resolve the target domain
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First, check if the domain already resolves to our target IP
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, e.config.TargetDomain)
	if err == nil {
		for _, ip := range ips {
			if ip.IP.String() == e.config.RedirectIP {
				info.HostsFileWorks = true
				log.Printf("Hosts file appears to be working for %s", e.config.TargetDomain)
				return nil
			}
		}
	}

	// If not resolving to our IP, hosts file is probably not working or not configured
	log.Printf("Hosts file does not appear to be working for %s", e.config.TargetDomain)
	return nil
}

// detectDNSProxy attempts to detect if a DNS proxy is intercepting queries
func (e *EnvironmentAnalyzer) detectDNSProxy(info *EnvironmentInfo) error {
	// Check DNS server configuration
	if runtime.GOOS == "windows" {
		if output, err := runCommand("ipconfig", "/all"); err == nil {
			outputStr := string(output)
			
			// Look for virtualization-specific DNS servers
			if strings.Contains(outputStr, "prl-local-ns-server") ||
			   strings.Contains(outputStr, "10.211.55.1") {
				info.DNSProxyDetected = true
				log.Printf("Detected Parallels DNS proxy")
			} else if strings.Contains(outputStr, "vmware") {
				info.DNSProxyDetected = true
				log.Printf("Detected VMware DNS proxy")
			}
		}
	} else if runtime.GOOS == "darwin" {
		if output, err := runCommand("scutil", "--dns"); err == nil {
			outputStr := string(output)
			
			// Look for virtualization-specific resolvers
			if strings.Contains(outputStr, "10.211.55.1") {
				info.DNSProxyDetected = true
				log.Printf("Detected Parallels DNS proxy")
			}
		}
	}

	return nil
}

// checkCapabilities checks what DNS interception capabilities are available
func (e *EnvironmentAnalyzer) checkCapabilities(info *EnvironmentInfo) {
	switch runtime.GOOS {
	case "windows":
		// Check for WFP support (Windows Vista+)
		info.Capabilities["wfp"] = true // Assume available on modern Windows
		
		// Check for administrative privileges
		if output, err := runCommand("net", "session"); err == nil && len(output) > 0 {
			info.Capabilities["admin"] = true
		}
		
		// API hooking is generally available
		info.Capabilities["api_hooking"] = true
		
	case "darwin":
		// Check for root privileges
		if _, err := runCommand("id", "-u"); err == nil {
			info.Capabilities["root"] = true
		}
		
		// pfctl is available on macOS
		if _, err := runCommand("which", "pfctl"); err == nil {
			info.Capabilities["pfctl"] = true
		}
		
		// Check System Integrity Protection status
		if output, err := runCommand("csrutil", "status"); err == nil {
			if !strings.Contains(string(output), "disabled") {
				info.Capabilities["sip_enabled"] = true
			}
		}
	}
}

// runCommand is a helper to run system commands
func runCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// DiagnosticInfo provides detailed diagnostic information about DNS interception
type DiagnosticInfo struct {
	Environment      *EnvironmentInfo
	CurrentMethod    InterceptionMethod
	ResolutionWorks  bool
	LastError        string
	Recommendations  []string
}

// GetDiagnosticInfo returns comprehensive diagnostic information
func (e *EnvironmentAnalyzer) GetDiagnosticInfo(interceptor *Interceptor) *DiagnosticInfo {
	info, _ := e.AnalyzeEnvironment()
	
	diag := &DiagnosticInfo{
		Environment:     info,
		CurrentMethod:   -1,
		ResolutionWorks: false,
		Recommendations: make([]string, 0),
	}

	if interceptor != nil {
		diag.CurrentMethod = interceptor.active
		diag.ResolutionWorks = interceptor.testResolution()
	}

	// Generate recommendations
	if !diag.ResolutionWorks {
		if info.IsVirtualized && info.VirtualTech == "Parallels" {
			diag.Recommendations = append(diag.Recommendations,
				"Detected Parallels Desktop: Consider disabling DNS proxy in VM settings")
		}
		
		if info.DNSProxyDetected {
			diag.Recommendations = append(diag.Recommendations,
				"DNS proxy detected: Advanced interception methods recommended")
		}
		
		if !info.Capabilities["admin"] && runtime.GOOS == "windows" {
			diag.Recommendations = append(diag.Recommendations,
				"Administrative privileges required for advanced DNS interception")
		}
		
		if !info.Capabilities["root"] && runtime.GOOS == "darwin" {
			diag.Recommendations = append(diag.Recommendations,
				"Root privileges required for advanced DNS interception")
		}
	}

	return diag
}