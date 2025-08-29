package config

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Config holds the AuthRouter configuration
type Config struct {
	// Core SAML settings
	TeamName    string
	SamlInitURL string
	
	// SSL/TLS settings
	SSLCert string
	SSLKey  string
	
	// Runtime state
	CertificateExpired bool // Set to true when certificate has expired
}

// Load reads configuration from production sources:
// 1. macOS: Managed Preferences (MDM/Jamf Configuration Profiles)
// 2. Both: Command-line flags (from LaunchDaemon plist or Windows service registry)
// Note: Config files are NOT used in production deployments
func Load() (*Config, error) {
	// Default configuration - use absolute paths for service compatibility
	certDir := ""
	if runtime.GOOS == "windows" {
		// Windows: Store certs in auth subdirectory alongside service binary
		certDir = filepath.Join(os.Getenv("PROGRAMFILES"), "Postman", "Postman Enterprise", "auth")
	} else if runtime.GOOS == "darwin" {
		// macOS: Store certs alongside daemon binary
		certDir = "/usr/local/bin/postman"
	}
	
	cfg := &Config{
		SSLCert: filepath.Join(certDir, "identity.getpostman.com.crt"),
		SSLKey:  filepath.Join(certDir, "identity.getpostman.com.key"),
	}

	// macOS: Check managed preferences first (MDM/Jamf Configuration Profiles)
	if runtime.GOOS == "darwin" {
		if teamName := getManagedPreference("teamName"); teamName != "" {
			cfg.TeamName = teamName
		}
		if samlUrl := getManagedPreference("samlUrl"); samlUrl != "" {
			cfg.SamlInitURL = samlUrl
		}
	}

	// Both platforms: Check command-line flags (from service configuration)
	// Parse flags if not already parsed
	if !flag.Parsed() {
		flag.Parse()
	}
	
	// Get team and saml-url flags
	teamFlag := flag.Lookup("team")
	samlFlag := flag.Lookup("saml-url")
	
	// Use command-line flags if provided (these come from LaunchDaemon plist or Windows service)
	if teamFlag != nil && teamFlag.Value.String() != "" {
		cfg.TeamName = teamFlag.Value.String()
	}
	if samlFlag != nil && samlFlag.Value.String() != "" {
		cfg.SamlInitURL = samlFlag.Value.String()
	}

	// Validate required fields
	if cfg.TeamName == "" || cfg.TeamName == "WILL_BE_CONFIGURED" {
		if runtime.GOOS == "darwin" {
			return nil, fmt.Errorf("team name not configured - set via MDM profile or --team flag in LaunchDaemon plist")
		}
		return nil, fmt.Errorf("team name not configured - set via --team flag in service configuration")
	}
	if cfg.SamlInitURL == "" || cfg.SamlInitURL == "WILL_BE_CONFIGURED" {
		if runtime.GOOS == "darwin" {
			return nil, fmt.Errorf("SAML URL not configured - set via MDM profile or --saml-url flag in LaunchDaemon plist")
		}
		return nil, fmt.Errorf("SAML URL not configured - set via --saml-url flag in service configuration")
	}

	return cfg, nil
}


// getManagedPreference reads a preference from macOS managed preferences (MDM/Jamf)
func getManagedPreference(key string) string {
	// Try to read from managed preferences using defaults command
	// This reads from /Library/Managed Preferences/com.postman.pm-authrouter.plist
	cmd := exec.Command("defaults", "read", "/Library/Managed Preferences/com.postman.pm-authrouter", key)
	output, err := cmd.Output()
	if err != nil {
		// Preference not found or not configured
		return ""
	}
	
	// Clean up the output (remove newlines and extra spaces)
	value := strings.TrimSpace(string(output))
	
	// Log that we found a managed preference
	if value != "" {
		// Use fmt.Printf since log might not be configured yet
		fmt.Printf("Found managed preference %s: %s\n", key, value)
	}
	
	return value
}