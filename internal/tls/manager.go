package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"pm-authrouter/internal/config"
)

// Manager handles TLS certificate validation and configuration
type Manager struct {
	config *config.Config
}

// NewManager creates a new TLS manager
func NewManager(cfg *config.Config) *Manager {
	return &Manager{config: cfg}
}

// EnsureValidCertificates checks that certificates exist - does NOT generate or trust them
// Certificate generation is handled by PKG/MSI installation
// Certificate trust is handled by MDM deployment (macOS) or MSI installation (Windows)
func (m *Manager) EnsureValidCertificates() (certPath, keyPath string, err error) {
	certPath = m.config.SSLCert
	keyPath = m.config.SSLKey

	// Check if certificates exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("certificate not found at %s - please reinstall the package", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("private key not found at %s - please reinstall the package", keyPath)
	}

	// Validate certificate format and expiration
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return "", "", fmt.Errorf("invalid certificate format")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	if cert.NotAfter.Before(time.Now()) {
		return "", "", fmt.Errorf("certificate expired on %v - please reinstall the package", cert.NotAfter)
	}

	// Warn if certificate is expiring soon
	thirtyDaysFromNow := time.Now().Add(30 * 24 * time.Hour)
	if cert.NotAfter.Before(thirtyDaysFromNow) {
		log.Printf("WARNING: Certificate expires on %v (within 30 days)", cert.NotAfter)
		log.Println("Please redeploy the package to generate new certificates")
	}

	log.Printf("Using certificate (valid until %v)", cert.NotAfter)
	
	// Check trust status and warn if not trusted
	if !m.IsCertificateTrusted() {
		log.Println("WARNING: Certificate is not trusted in system keychain")
		if runtime.GOOS == "darwin" {
			log.Println("Deploy the MDM configuration profile to establish trust")
		} else {
			log.Println("Certificate trust should be established during MSI installation")
		}
	}

	return certPath, keyPath, nil
}

// LoadTLSConfig loads the TLS configuration for the HTTPS server
func (m *Manager) LoadTLSConfig() (*tls.Config, error) {
	certPath, keyPath, err := m.EnsureValidCertificates()
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "identity.getpostman.com",
	}, nil
}

// IsCertificateTrusted checks if the certificate is trusted in the system keychain
func (m *Manager) IsCertificateTrusted() bool {
	certPath := m.config.SSLCert
	
	switch runtime.GOOS {
	case "darwin":
		return m.isCertificateTrustedMacOS(certPath)
	case "windows":
		return m.isCertificateTrustedWindows()
	default:
		// Unsupported OS - assume not trusted
		return false
	}
}

// isCertificateTrustedMacOS checks if certificate is trusted on macOS
func (m *Manager) isCertificateTrustedMacOS(certPath string) bool {
	// First check if our specific certificate exists by SHA1 fingerprint
	// This prevents duplicate checking and ensures we're checking the RIGHT cert
	
	// Get SHA1 of our certificate file
	sha1Cmd := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-fingerprint", "-sha1")
	sha1Output, err := sha1Cmd.Output()
	if err != nil {
		log.Printf("Failed to get certificate SHA1: %v", err)
		return false
	}
	
	// Extract just the hex fingerprint (remove "SHA1 Fingerprint=" prefix and colons)
	sha1Str := strings.TrimSpace(string(sha1Output))
	if idx := strings.Index(sha1Str, "="); idx != -1 {
		sha1Str = sha1Str[idx+1:]
	}
	sha1Str = strings.ReplaceAll(sha1Str, ":", "")
	sha1Str = strings.ToLower(sha1Str)
	
	// Check if this exact certificate is in System keychain
	findCmd := exec.Command("security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
	findOutput, err := findCmd.Output()
	if err != nil {
		return false
	}
	
	// Look for our SHA1 in the output (security outputs SHA1 without colons)
	if !strings.Contains(strings.ToLower(string(findOutput)), sha1Str) {
		// Certificate not found in keychain
		return false
	}
	
	// Certificate exists, now verify it's trusted for SSL
	verifyCmd := exec.Command("security", "verify-cert", "-c", certPath, "-p", "ssl")
	if output, err := verifyCmd.CombinedOutput(); err != nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "CSSMERR_TP_NOT_TRUSTED") || 
		   strings.Contains(outputStr, "SecTrustEvaluateWithError") ||
		   strings.Contains(outputStr, "certificate is not trusted") {
			// Certificate is installed but not trusted
			return false
		}
		// Other verification error
		return false
	}
	
	return true
}

// isCertificateTrustedWindows checks if certificate is trusted on Windows
func (m *Manager) isCertificateTrustedWindows() bool {
	// Use certutil to check if certificate is in trusted root store
	cmd := exec.Command("certutil.exe", "-verifystore", "Root", "identity.getpostman.com")
	if output, err := cmd.CombinedOutput(); err != nil {
		return false
	} else {
		outputStr := string(output)
		if strings.Contains(outputStr, "Certificate is valid") || 
		   strings.Contains(outputStr, "CertUtil: -verifystore command completed successfully") {
			return true
		}
	}
	return false
}