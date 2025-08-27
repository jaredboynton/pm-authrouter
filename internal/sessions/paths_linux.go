//go:build linux

package sessions

import (
	"os"
	"path/filepath"
)

// getChromeProfilePaths returns Chrome profile paths on Linux
func getChromeProfilePaths() []string {
	var paths []string
	
	home, err := os.UserHomeDir()
	if err != nil {
		return paths
	}
	
	// Chrome default profile
	chromePath := filepath.Join(home, ".config", "google-chrome", "Default")
	if _, err := os.Stat(chromePath); err == nil {
		paths = append(paths, chromePath)
	}
	
	// Chromium default profile
	chromiumPath := filepath.Join(home, ".config", "chromium", "Default")
	if _, err := os.Stat(chromiumPath); err == nil {
		paths = append(paths, chromiumPath)
	}
	
	return paths
}

// getFirefoxProfilePaths returns Firefox profile paths on Linux
func getFirefoxProfilePaths() []string {
	var paths []string
	
	home, err := os.UserHomeDir()
	if err != nil {
		return paths
	}
	
	firefoxProfiles := filepath.Join(home, ".mozilla", "firefox")
	if entries, err := os.ReadDir(firefoxProfiles); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && filepath.Ext(entry.Name()) == ".default" {
				profilePath := filepath.Join(firefoxProfiles, entry.Name())
				paths = append(paths, profilePath)
			}
		}
	}
	
	return paths
}

// getSafariCookiePath returns empty string on Linux (Safari not available)
func getSafariCookiePath() string {
	return ""
}

// getEdgeProfilePaths returns Edge profile paths on Linux
func getEdgeProfilePaths() []string {
	var paths []string
	
	home, err := os.UserHomeDir()
	if err != nil {
		return paths
	}
	
	// Edge default profile on Linux
	edgePath := filepath.Join(home, ".config", "microsoft-edge", "Default")
	if _, err := os.Stat(edgePath); err == nil {
		paths = append(paths, edgePath)
	}
	
	return paths
}