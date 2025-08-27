package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// proxyToUpstream implements the full upstream proxy with SNI support
func (h *Handler) proxyToUpstream(w http.ResponseWriter, r *http.Request, host, path, method string) {
	// Only identity.getpostman.com is intercepted (in hosts file)
	if host != "identity.getpostman.com" {
		log.Printf("Unexpected host in proxy: %s", host)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Get real IP address for the host using DNS resolver
	resolver := NewDNSResolver(nil) // Use default DNS servers
	upstreamIP, err := resolver.ResolveRealIP(host)
	if err != nil {
		log.Printf("DNS resolution failed: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	log.Printf("Proxying to upstream %s (%s)", host, upstreamIP)

	// Create HTTP client with custom transport
	// Key settings to preserve exact response bytes
	client := &http.Client{
		Transport: &http.Transport{
			// Custom dialer to use our resolved IP but maintain SNI
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Always connect to our resolved IP on port 443
				return net.Dial(network, fmt.Sprintf("%s:443", upstreamIP))
			},
			TLSClientConfig: &tls.Config{
				ServerName: host, // Critical: Set SNI to original hostname for CDN
			},
			// Critical settings to avoid modifying response
			DisableCompression: true,        // Don't auto-decompress gzip/deflate
			ForceAttemptHTTP2:  false,       // Stay HTTP/1.1 for compatibility
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
		},
		// Don't follow redirects - let client handle them
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	// Build upstream URL
	upstreamURL := fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())

	// Create new request - use r.Body directly to avoid double-reading
	upstreamReq, err := http.NewRequestWithContext(r.Context(), method, upstreamURL, r.Body)
	if err != nil {
		log.Printf("Failed to create upstream request: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Copy headers (skip hop-by-hop headers)
	hopByHopHeaders := map[string]bool{
		"connection":          true,
		"keep-alive":         true,
		"proxy-authenticate": true,
		"proxy-authorization": true,
		"te":                 true,
		"trailers":           true,
		"transfer-encoding":  true,
		"upgrade":            true,
	}

	for name, values := range r.Header {
		if !hopByHopHeaders[strings.ToLower(name)] {
			for _, value := range values {
				upstreamReq.Header.Add(name, value)
			}
		}
	}

	// Make the request
	resp, err := client.Do(upstreamReq)
	if err != nil {
		log.Printf("Upstream request failed: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers (skip hop-by-hop)
	for name, values := range resp.Header {
		if !hopByHopHeaders[strings.ToLower(name)] {
			// Use Set for first value, Add for additional values
			// This preserves multiple Set-Cookie headers correctly
			w.Header()[name] = values
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Stream the body directly - this is the KEY
	// io.Copy preserves exact bytes without modification
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Failed to copy response body: %v (wrote %d bytes)", err, written)
		// Can't send error response as headers are already sent
	} else {
		log.Printf("Successfully proxied response: %d %s (%d bytes)", resp.StatusCode, http.StatusText(resp.StatusCode), written)
	}
}