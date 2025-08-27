package sessions

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ClearPostmanSessions clears Postman-related sessions from all browsers
func ClearPostmanSessions() error {
	var errors []error
	
	// Clear Chrome/Chromium cookies
	if err := clearChromeCookies(); err != nil {
		errors = append(errors, fmt.Errorf("chrome: %w", err))
	}
	
	// Clear Firefox cookies
	if err := clearFirefoxCookies(); err != nil {
		errors = append(errors, fmt.Errorf("firefox: %w", err))
	}
	
	// Clear Safari cookies (macOS only)
	if runtime.GOOS == "darwin" {
		if err := clearSafariCookies(); err != nil {
			errors = append(errors, fmt.Errorf("safari: %w", err))
		}
	}
	
	// Clear Edge cookies (Windows only)
	if runtime.GOOS == "windows" {
		if err := clearEdgeCookies(); err != nil {
			errors = append(errors, fmt.Errorf("edge: %w", err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("failed to clear some sessions: %v", errors)
	}
	
	return nil
}

// clearChromeCookies clears Chrome/Chromium cookies using direct binary manipulation
func clearChromeCookies() error {
	cookiePaths := getChromeProfilePaths()
	
	for _, profilePath := range cookiePaths {
		cookieDB := filepath.Join(profilePath, "Cookies")
		if _, err := os.Stat(cookieDB); err != nil {
			continue // Skip if file doesn't exist
		}
		
		if err := nullifyDomainsInFile(cookieDB, getPostmanDomains()); err != nil {
			return fmt.Errorf("failed to clear cookies in %s: %w", cookieDB, err)
		}
	}
	
	return nil
}

// clearFirefoxCookies clears Firefox cookies using direct binary manipulation
func clearFirefoxCookies() error {
	profilePaths := getFirefoxProfilePaths()
	
	for _, profilePath := range profilePaths {
		cookieDB := filepath.Join(profilePath, "cookies.sqlite")
		if _, err := os.Stat(cookieDB); err != nil {
			continue // Skip if file doesn't exist
		}
		
		if err := nullifyDomainsInFile(cookieDB, getPostmanDomains()); err != nil {
			return fmt.Errorf("failed to clear cookies in %s: %w", cookieDB, err)
		}
	}
	
	return nil
}

// clearSafariCookies clears Safari cookies using direct binary manipulation
func clearSafariCookies() error {
	cookiePath := getSafariCookiePath()
	if cookiePath == "" {
		return nil // Safari not installed or no cookies
	}
	
	// Safari uses binary plist format for cookies
	data, err := os.ReadFile(cookiePath)
	if err != nil {
		return err
	}
	
	// Safari stores domains with a prefix character
	safariDomains := [][]byte{
		[]byte("Apostman.com"),
		[]byte("A.postman.com"),
		[]byte("Aidentity.getpostman.com"),
		[]byte("Aapp.getpostman.com"),
	}
	
	modified := false
	for _, domain := range safariDomains {
		newData := bytes.ReplaceAll(data, domain, bytes.Repeat([]byte{0}, len(domain)))
		if !bytes.Equal(data, newData) {
			data = newData
			modified = true
		}
	}
	
	if modified {
		return os.WriteFile(cookiePath, data, 0644)
	}
	
	return nil
}

// clearEdgeCookies clears Edge cookies using direct binary manipulation
func clearEdgeCookies() error {
	cookiePaths := getEdgeProfilePaths()
	
	for _, profilePath := range cookiePaths {
		cookieDB := filepath.Join(profilePath, "Cookies")
		if _, err := os.Stat(cookieDB); err != nil {
			continue // Skip if file doesn't exist
		}
		
		if err := nullifyDomainsInFile(cookieDB, getPostmanDomains()); err != nil {
			return fmt.Errorf("failed to clear cookies in %s: %w", cookieDB, err)
		}
	}
	
	return nil
}

// nullifyDomainsInFile nulls out domain strings in a binary file
func nullifyDomainsInFile(filePath string, domains []string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	
	modified := false
	for _, domain := range domains {
		domainBytes := []byte(domain)
		
		// Find and null out all occurrences
		for i := 0; i <= len(data)-len(domainBytes); i++ {
			if bytes.Equal(data[i:i+len(domainBytes)], domainBytes) {
				// Null out the domain
				for j := 0; j < len(domainBytes); j++ {
					data[i+j] = 0
				}
				modified = true
				i += len(domainBytes) - 1 // Skip past this occurrence
			}
		}
	}
	
	if modified {
		return os.WriteFile(filePath, data, 0644)
	}
	
	return nil
}

// getPostmanDomains returns list of Postman-related domains to clear
func getPostmanDomains() []string {
	return []string{
		"postman.com",
		".postman.com",
		"getpostman.com",
		".getpostman.com",
		"identity.getpostman.com",
		"app.getpostman.com",
		"postman.co",
		".postman.co",
	}
}