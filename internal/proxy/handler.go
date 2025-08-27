package proxy

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"pm-authrouter/internal/config"
)

// Handler handles incoming HTTP requests
type Handler struct {
	config *config.Config
}

// NewHandler creates a new request handler
func NewHandler(cfg *config.Config) *Handler {
	return &Handler{config: cfg}
}

// ServeHTTP implements the http.Handler interface
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("Host")
	if host == "" {
		host = r.Host
	}
	path := r.URL.RequestURI() // Full path with query string like Python's self.path
	method := r.Method

	// Log request for debugging (debug level like Python)
	log.Printf("%s %s%s", method, host, path)

	// Parse query parameters 
	query := r.URL.Query()

	// Health check endpoint for daemon monitoring
	if host == "identity.getpostman.com" && r.URL.Path == "/health" {
		h.handleHealthCheck(w, r)
		return
	}

	// CORE LOGIC: Only intercept /login on identity.getpostman.com for SAML enforcement
	// Strip trailing slash for consistent matching (exactly like Python rstrip('/'))
	cleanPath := strings.TrimRight(r.URL.Path, "/")
	interceptPaths := []string{"/login", "/enterprise/login", "/enterprise/login/authchooser"}
	
	if host == "identity.getpostman.com" {
		for _, interceptPath := range interceptPaths {
			if cleanPath == interceptPath {
				authChallenge := query.Get("auth_challenge")
				log.Printf("Intercepting %s %s%s - redirecting to SAML", method, host, path)
				h.handleSAMLRedirect(w, r, query, authChallenge)
				return
			}
		}
	}

	// Everything else passes through to upstream
	log.Printf("Passing through %s %s%s", method, host, path)
	h.proxyToUpstream(w, r, host, path, method)
}

// handleSAMLRedirect handles SAML redirect for both Postman desktop and web flows (replicates Python logic exactly)
func (h *Handler) handleSAMLRedirect(w http.ResponseWriter, r *http.Request, query url.Values, authChallenge string) {
	var samlURL string

	if authChallenge != "" {
		// Postman desktop flow with auth_challenge
		log.Println("Postman desktop flow detected - redirecting to SAML with auth_challenge")
		samlURL = h.getSAMLRedirectURL(authChallenge, "", "")
		
		// Add auth_device parameter if present to ensure desktop app redirect
		if authDevice := query.Get("auth_device"); authDevice != "" {
			parsedURL, err := url.Parse(samlURL)
			if err == nil {
				params := parsedURL.Query()
				params.Set("auth_device", authDevice)
				parsedURL.RawQuery = params.Encode()
				samlURL = parsedURL.String()
			}
		}
	} else {
		// Postman web flow without auth_challenge
		log.Println("Postman web flow detected - redirecting to SAML with team")
		teamName := h.config.TeamName
		continueURL := query.Get("continue")
		samlURL = h.getSAMLRedirectURL("", teamName, continueURL)
	}

	log.Printf("SAML redirect: %s", samlURL)

	// Send 302 redirect
	w.Header().Set("Location", samlURL)
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusFound)
}

// handleHealthCheck handles health check requests
func (h *Handler) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	log.Printf("Health check request received")

	// Send simple 200 OK response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)

	// Send simple health status
	healthData := map[string]interface{}{
		"status":    "healthy",
		"service":   "pm-authrouter",
		"timestamp": time.Now().Unix(),
	}

	json.NewEncoder(w).Encode(healthData)
}

// getSAMLRedirectURL generates SAML redirect URL based on IdP configuration
func (h *Handler) getSAMLRedirectURL(authChallenge, team, continueURL string) string {
	// Use configured team name if not provided
	if team == "" {
		team = h.config.TeamName
	}

	// Use configured SAML init URL directly
	baseSAMLURL := h.config.SamlInitURL
	if baseSAMLURL == "" {
		baseSAMLURL = "https://identity.getpostman.com/sso/saml/init"
	}

	// Parse the base URL
	parsedURL, err := url.Parse(baseSAMLURL)
	if err != nil {
		log.Printf("Error parsing SAML URL: %v", err)
		return baseSAMLURL
	}

	// Build query parameters
	queryParams := url.Values{}
	queryParams.Set("team", team)

	// Add Postman desktop-specific parameters
	if authChallenge != "" {
		queryParams.Set("auth_challenge", authChallenge)
	}

	// Add Postman web-specific parameters
	if continueURL != "" {
		queryParams.Set("continue", continueURL)
	}

	// Combine existing query params (if any) with new ones
	if parsedURL.RawQuery != "" {
		existingParams, _ := url.ParseQuery(parsedURL.RawQuery)
		for key, values := range queryParams {
			for _, value := range values {
				existingParams.Add(key, value)
			}
		}
		parsedURL.RawQuery = existingParams.Encode()
	} else {
		parsedURL.RawQuery = queryParams.Encode()
	}

	return parsedURL.String()
}

// proxyToUpstream is implemented in upstream.go