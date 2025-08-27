//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// checkWindowsAdmin checks if running as administrator on Windows
func checkWindowsAdmin() error {
	// Use PowerShell to check if running as admin
	cmd := exec.Command("powershell", "-Command", "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check admin privileges: %w", err)
	}

	isAdmin := strings.TrimSpace(string(output)) == "True"
	if !isAdmin {
		return fmt.Errorf(`
================================================================
⚠️  ADMINISTRATOR PRIVILEGES REQUIRED
================================================================

This daemon requires administrator access to:
  • Bind to port 443 (HTTPS)
  • Modify hosts file
  • Install certificates to trust store

Please run PowerShell as Administrator and try again.
================================================================`)
	}

	return nil
}

// checkPrivileges verifies the process has the required privileges to run
func checkPrivileges() error {
	return checkWindowsAdmin()
}