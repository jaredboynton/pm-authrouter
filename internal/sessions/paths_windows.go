//go:build windows

package sessions

import (
	"os"
	"path/filepath"
)

// getChromeProfilePaths returns Chrome profile paths on Windows
func getChromeProfilePaths() []string {
	var paths []string
	
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return paths
	}
	
	// Chrome default profile
	chromePath := filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default")
	if _, err := os.Stat(chromePath); err == nil {
		paths = append(paths, chromePath)
	}
	
	// Chrome additional profiles
	chromeUserData := filepath.Join(localAppData, "Google", "Chrome", "User Data")
	if entries, err := os.ReadDir(chromeUserData); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && (entry.Name() == "Default" || 
				(len(entry.Name()) > 7 && entry.Name()[:7] == "Profile")) {
				profilePath := filepath.Join(chromeUserData, entry.Name())
				paths = append(paths, profilePath)
			}
		}
	}
	
	return paths
}

// getFirefoxProfilePaths returns Firefox profile paths on Windows
func getFirefoxProfilePaths() []string {
	var paths []string
	
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return paths
	}
	
	firefoxProfiles := filepath.Join(appData, "Mozilla", "Firefox", "Profiles")
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

// getSafariCookiePath returns empty string on Windows (Safari not available)
func getSafariCookiePath() string {
	return ""
}

// getEdgeProfilePaths returns Edge profile paths on Windows
func getEdgeProfilePaths() []string {
	var paths []string
	
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return paths
	}
	
	// Edge default profile
	edgePath := filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default")
	if _, err := os.Stat(edgePath); err == nil {
		paths = append(paths, edgePath)
	}
	
	// Edge additional profiles
	edgeUserData := filepath.Join(localAppData, "Microsoft", "Edge", "User Data")
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