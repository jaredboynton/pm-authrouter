//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// checkUnixRoot checks if running as root on Unix-like systems
func checkUnixRoot() error {
	if os.Geteuid() != 0 {
		executable, _ := os.Executable()
		executableName := filepath.Base(executable)

		return fmt.Errorf(`
================================================================
⚠️  ROOT PRIVILEGES REQUIRED
================================================================

This daemon requires root access to:
  • Bind to port 443 (HTTPS)
  • Modify /etc/hosts file
  • Install certificates to system keychain

Please run with sudo:
  sudo %s

================================================================`, executableName)
	}

	return nil
}

// checkPrivileges verifies the process has the required privileges to run
func checkPrivileges() error {
	return checkUnixRoot()
}