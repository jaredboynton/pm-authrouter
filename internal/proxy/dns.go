package proxy

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// DNSResolver handles DNS resolution bypassing /etc/hosts modifications
type DNSResolver struct {
	servers []string
	timeout time.Duration
}

// NewDNSResolver creates a new DNS resolver with fallback servers
func NewDNSResolver(servers []string) *DNSResolver {
	if len(servers) == 0 {
		servers = []string{"8.8.8.8", "1.1.1.1"} // Default fallback servers
	}
	
	return &DNSResolver{
		servers: servers,
		timeout: 5 * time.Second,
	}
}

// ResolveRealIP resolves hostname to real IP address bypassing /etc/hosts
func (r *DNSResolver) ResolveRealIP(hostname string) (string, error) {
	// Try each DNS server in order
	for _, dnsServer := range r.servers {
		ip, err := r.queryDNSServer(hostname, dnsServer)
		if err == nil && ip != "" {
			return ip, nil
		}
	}
	
	return "", fmt.Errorf("unable to resolve %s - check network connectivity", hostname)
}

// queryDNSServer queries a specific DNS server for hostname resolution
func (r *DNSResolver) queryDNSServer(hostname, dnsServer string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		return r.queryDNSWindows(hostname, dnsServer)
	default:
		return r.queryDNSUnix(hostname, dnsServer)
	}
}

// queryDNSWindows uses nslookup on Windows
func (r *DNSResolver) queryDNSWindows(hostname, dnsServer string) (string, error) {
	cmd := exec.Command("nslookup", hostname, dnsServer)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("nslookup failed: %w", err)
	}
	
	lines := strings.Split(string(output), "\n")
	inAddresses := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Check for "Addresses:" or "Address:" section
		if strings.HasPrefix(line, "Addresses:") || strings.HasPrefix(line, "Address:") {
			// Skip the DNS server address line (contains the DNS server IP)
			if strings.Contains(line, dnsServer) {
				continue
			}
			
			// Try to extract IP from same line (single address case)
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ip := strings.TrimSpace(parts[1])
				// Skip IPv6 addresses for now (use IPv4)
				if net.ParseIP(ip) != nil && !strings.Contains(ip, ":") {
					return ip, nil
				}
			}
			inAddresses = true
			continue
		}
		
		// If we're in the addresses section, parse subsequent lines
		if inAddresses {
			// Skip empty lines and section headers
			if line == "" || strings.HasPrefix(line, "Aliases:") || strings.HasPrefix(line, "Name:") {
				inAddresses = false
				continue
			}
			
			// Clean up the IP address (remove tabs and spaces)
			ip := strings.TrimSpace(line)
			// Skip IPv6 addresses (contain colons)
			if net.ParseIP(ip) != nil && !strings.Contains(ip, ":") {
				return ip, nil
			}
		}
	}
	
	return "", fmt.Errorf("no valid IP address found in nslookup output")
}

// queryDNSUnix uses nslookup on Unix-like systems
func (r *DNSResolver) queryDNSUnix(hostname, dnsServer string) (string, error) {
	cmd := exec.Command("nslookup", hostname, dnsServer)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("nslookup failed: %w", err)
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Address:") && !strings.HasSuffix(line, "#53") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ip := strings.TrimSpace(strings.Join(parts[1:], ":"))
				// Handle IPv6 addresses that might have colons
				if net.ParseIP(ip) != nil {
					return ip, nil
				}
			}
		}
	}
	
	return "", fmt.Errorf("no valid IP address found in nslookup output")
}