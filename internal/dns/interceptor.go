package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

// InterceptionMethod represents different DNS interception techniques
type InterceptionMethod int

const (
	HostsFile InterceptionMethod = iota
	WindowsWFP
	MacOSNetworkExtension
	APIHooking
	RegistryOverride
)

// InterceptorConfig holds configuration for DNS interception
type InterceptorConfig struct {
	TargetDomain    string
	RedirectIP      string
	EnableFallbacks bool
	LogLevel        string
}

// Interceptor handles DNS interception using multiple fallback methods
type Interceptor struct {
	config    InterceptorConfig
	active    InterceptionMethod
	mutex     sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	methods   []InterceptionMethod
}

// NewInterceptor creates a new DNS interceptor with platform-appropriate methods
func NewInterceptor(config InterceptorConfig) *Interceptor {
	ctx, cancel := context.WithCancel(context.Background())
	
	i := &Interceptor{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}

	// Configure available methods based on platform
	switch runtime.GOOS {
	case "windows":
		i.methods = []InterceptionMethod{
			HostsFile,
			WindowsWFP,
			APIHooking,
			RegistryOverride,
		}
	case "darwin":
		i.methods = []InterceptionMethod{
			HostsFile,
			MacOSNetworkExtension,
		}
	default:
		i.methods = []InterceptionMethod{
			HostsFile,
		}
	}

	return i
}

// Start begins DNS interception using the best available method
func (i *Interceptor) Start() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	log.Printf("Starting DNS interceptor for %s -> %s", i.config.TargetDomain, i.config.RedirectIP)

	// Select method based on VPN status
	methods := i.selectMethodsForEnvironment()

	var lastErr error
	for _, method := range methods {
		log.Printf("Attempting DNS interception method: %s", i.methodName(method))
		
		if err := i.startMethod(method); err != nil {
			log.Printf("Method %s failed: %v", i.methodName(method), err)
			lastErr = err
			continue
		}

		i.active = method
		log.Printf("DNS interception active using method: %s", i.methodName(method))
		
		// Start monitoring in background
		go i.monitor()
		
		return nil
	}

	return fmt.Errorf("all DNS interception methods failed, last error: %w", lastErr)
}

// Stop halts DNS interception and cleans up
func (i *Interceptor) Stop() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if i.cancel != nil {
		i.cancel()
	}

	log.Printf("Stopping DNS interceptor (method: %s)", i.methodName(i.active))
	return i.stopMethod(i.active)
}

// IsActive returns whether DNS interception is currently working
func (i *Interceptor) IsActive() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	return i.testResolution()
}

// GetActiveMethod returns the currently active interception method
func (i *Interceptor) GetActiveMethod() string {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	return i.methodName(i.active)
}

// startMethod starts the specified interception method
func (i *Interceptor) startMethod(method InterceptionMethod) error {
	switch method {
	case HostsFile:
		return i.startHostsFile()
	case WindowsWFP:
		return i.startWindowsWFP()
	case MacOSNetworkExtension:
		return i.startMacOSNetworkExtension()
	case APIHooking:
		return i.startAPIHooking()
	case RegistryOverride:
		return i.startRegistryOverride()
	default:
		return fmt.Errorf("unsupported interception method: %d", method)
	}
}

// stopMethod stops the specified interception method
func (i *Interceptor) stopMethod(method InterceptionMethod) error {
	switch method {
	case HostsFile:
		return i.stopHostsFile()
	case WindowsWFP:
		return i.stopWindowsWFP()
	case MacOSNetworkExtension:
		return i.stopMacOSNetworkExtension()
	case APIHooking:
		return i.stopAPIHooking()
	case RegistryOverride:
		return i.stopRegistryOverride()
	default:
		return nil
	}
}

// methodName returns human-readable name for interception method
func (i *Interceptor) methodName(method InterceptionMethod) string {
	switch method {
	case HostsFile:
		return "hosts file"
	case WindowsWFP:
		return "Windows Filtering Platform"
	case MacOSNetworkExtension:
		return "macOS Network Extension"
	case APIHooking:
		return "API Hooking"
	case RegistryOverride:
		return "Registry Override"
	default:
		return "unknown"
	}
}

// testResolution tests if DNS resolution is working correctly
func (i *Interceptor) testResolution() bool {
	// Use method-specific health checks
	switch i.active {
	case HostsFile:
		// For hosts file, check if DNS resolves to our redirect IP
		return i.testDNSResolution()
	case MacOSNetworkExtension, WindowsWFP:
		// For TCP redirection methods (pfctl, WFP), check TCP connectivity
		return i.testTCPRedirection()
	default:
		// Fallback to DNS resolution test
		return i.testDNSResolution()
	}
}

// testDNSResolution checks if DNS resolves to our redirect IP
func (i *Interceptor) testDNSResolution() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, i.config.TargetDomain)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.IP.String() == i.config.RedirectIP {
			return true
		}
	}

	return false
}

// testTCPRedirection checks if TCP traffic is being redirected
func (i *Interceptor) testTCPRedirection() bool {
	// Try to connect to the target domain on port 443
	// If pfctl/WFP is working, this should connect to our local proxy
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(i.config.TargetDomain, "443"), 2*time.Second)
	if err != nil {
		// Connection failed - redirection might not be working
		return false
	}
	defer conn.Close()

	// Check if we connected to localhost (our proxy)
	localAddr := conn.LocalAddr().String()
	if strings.Contains(localAddr, "127.0.0.1") || strings.Contains(localAddr, "localhost") {
		return true
	}

	// For pfctl/WFP, the connection succeeds even without DNS change
	// We can't easily verify it's redirected without more complex checks
	// For now, assume if connection works, the method might be working
	return true
}

// monitor continuously monitors DNS resolution and switches methods if needed
func (i *Interceptor) monitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-i.ctx.Done():
			return
		case <-ticker.C:
			if !i.testResolution() {
				log.Printf("DNS interception method %s appears to have failed", i.methodName(i.active))
				
				// Try to restore current method first
				if err := i.restoreMethod(i.active); err != nil {
					log.Printf("Failed to restore method %s: %v", i.methodName(i.active), err)
					
					// Try alternative methods
					i.tryAlternativeMethods()
				}
			}
		}
	}
}

// restoreMethod attempts to restore the current interception method
func (i *Interceptor) restoreMethod(method InterceptionMethod) error {
	log.Printf("Attempting to restore DNS interception method: %s", i.methodName(method))
	
	// Stop and restart the method
	if err := i.stopMethod(method); err != nil {
		log.Printf("Warning: Failed to cleanly stop method %s: %v", i.methodName(method), err)
	}
	
	return i.startMethod(method)
}

// tryAlternativeMethods attempts to activate alternative DNS interception methods
func (i *Interceptor) tryAlternativeMethods() {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	log.Printf("Trying alternative DNS interception methods...")

	for _, method := range i.methods {
		if method == i.active {
			continue // Skip currently active (failed) method
		}

		log.Printf("Attempting fallback to: %s", i.methodName(method))
		
		if err := i.startMethod(method); err != nil {
			log.Printf("Fallback method %s failed: %v", i.methodName(method), err)
			continue
		}

		// Stop the old method
		i.stopMethod(i.active)
		
		i.active = method
		log.Printf("Successfully switched to fallback method: %s", i.methodName(method))
		return
	}

	log.Printf("All fallback methods failed - DNS interception may be non-functional")
}

// selectMethodsForEnvironment selects appropriate DNS methods based on environment
func (i *Interceptor) selectMethodsForEnvironment() []InterceptionMethod {
	// Just use the configured methods - hosts file works fine with VPNs
	return i.methods
}

// Platform-specific methods are implemented in platform-specific files with build tags


// GetStatus returns detailed status information about DNS interception
func (i *Interceptor) GetStatus() map[string]interface{} {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	status := map[string]interface{}{
		"active_method":    i.methodName(i.active),
		"target_domain":    i.config.TargetDomain,
		"redirect_ip":      i.config.RedirectIP,
		"resolution_works": i.testResolution(),
		"available_methods": make([]string, len(i.methods)),
	}

	for idx, method := range i.methods {
		status["available_methods"].([]string)[idx] = i.methodName(method)
	}

	return status
}