//go:build darwin

package sessions

import (
	"os"
	"path/filepath"
)

// getChromeProfilePaths returns Chrome profile paths on macOS
func getChromeProfilePaths() []string {
	var paths []string
	
	home, err := os.UserHomeDir()
	if err != nil {
		return paths
	}
	
	// Chrome default profile
	chromePath := filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default")
	if _, err := os.Stat(chromePath); err == nil {
		paths = append(paths, chromePath)
	}
	
	// Chrome additional profiles
	chromeUserData := filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	if entries, err := os.ReadDir(chromeUserData); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && (entry.Name() == "Default" || 
				(len(entry.Name()) > 7 && entry.Name()[:7] == "Profile")) {
				profilePath := filepath.Join(chromeUserData, entry.Name())
				paths = append(paths, profilePath)
			}
		}
	}
	
	// Chromium paths
	chromiumPath := filepath.Join(home, "Library", "Application Support", "Chromium", "Default")
	if _, err := os.Stat(chromiumPath); err == nil {
		paths = append(paths, chromiumPath)
	}
	
	return paths
}

// getFirefoxProfilePaths returns Firefox profile paths on macOS
func getFirefoxProfilePaths() []string {
	var paths []string
	
	home, err := os.UserHomeDir()
	if err != nil {
		return paths
	}
	
	firefoxProfiles := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	if entries, err := os.ReadDir(firefoxProfiles); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				profilePath := filepath.Join(firefoxProfiles, entry.Name())
				paths = append(paths, profilePath)
			}
		}
	}
	
	return paths
}

// getSafariCookiePath returns Safari cookie path on macOS
func getSafariCookiePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	
	cookiePath := filepath.Join(home, "Library", "Cookies", "Cookies.binarycookies")
	if _, err := os.Stat(cookiePath); err == nil {
		return cookiePath
	}
	
	// Alternative location for newer macOS versions
	cookiePath = filepath.Join(home, "Library", "HTTPStorages", "com.apple.Safari", "Cookies.binarycookies")
	if _, err := os.Stat(cookiePath); err == nil {
		return cookiePath
	}
	
	return ""
}

// getEdgeProfilePaths returns empty slice on macOS (Edge uses Chrome paths)
func getEdgeProfilePaths() []string {
	var paths []string
	
	home, err := os.UserHomeDir()
	if err != nil {
		return paths
	}
	
	// Edge on macOS uses similar structure to Chrome
	edgePath := filepath.Join(home, "Library", "Application Support", "Microsoft Edge", "Default")
	if _, err := os.Stat(edgePath); err == nil {
		paths = append(paths, edgePath)
	}
	
	// Edge additional profiles
	edgeUserData := filepath.Join(home, "Library", "Application Support", "Microsoft Edge")
	if entries, err := os.ReadDir(edgeUserData); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && (entry.Name() == "Default" || 
				(len(entry.Name()) > 7 && entry.Name()[:7] == "Profile")) {
				profilePath := filepath.Join(edgeUserData, entry.Name())
				paths = append(paths, profilePath)
			}
		}
	}
	
	return paths
}