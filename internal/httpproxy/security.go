package httpproxy

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
)

// privateIPBlocks contains CIDR ranges for private/reserved IP addresses.
// Used to prevent SSRF attacks.
var privateIPBlocks = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),      // RFC1918
	mustParseCIDR("172.16.0.0/12"),   // RFC1918
	mustParseCIDR("192.168.0.0/16"),  // RFC1918
	mustParseCIDR("127.0.0.0/8"),     // Loopback
	mustParseCIDR("169.254.0.0/16"),  // Link-local
	mustParseCIDR("::1/128"),         // IPv6 loopback
	mustParseCIDR("fe80::/10"),       // IPv6 link-local
	mustParseCIDR("fc00::/7"),        // IPv6 unique local
	mustParseCIDR("0.0.0.0/8"),       // Current network
	mustParseCIDR("100.64.0.0/10"),   // Carrier-grade NAT
	mustParseCIDR("192.0.0.0/24"),    // IETF Protocol Assignments
	mustParseCIDR("192.0.2.0/24"),    // TEST-NET-1
	mustParseCIDR("198.51.100.0/24"), // TEST-NET-2
	mustParseCIDR("203.0.113.0/24"),  // TEST-NET-3
	mustParseCIDR("224.0.0.0/4"),     // Multicast
	mustParseCIDR("240.0.0.0/4"),     // Reserved
}

func mustParseCIDR(s string) *net.IPNet {
	_, block, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return block
}

// isPrivateIP checks if an IP is in a private/reserved range.
func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ErrSSRFBlocked is returned when a request targets a private IP.
var ErrSSRFBlocked = fmt.Errorf("request to private IP blocked")

// ErrRequestSmuggling is returned when request smuggling is detected.
var ErrRequestSmuggling = fmt.Errorf("potential request smuggling detected")

// validateRequestSecurity performs security checks on the request.
func validateRequestSecurity(req *http.Request) error {
	// Check for request smuggling (TE + CL combo)
	if err := checkRequestSmuggling(req); err != nil {
		return err
	}

	return nil
}

// checkRequestSmuggling detects potential HTTP request smuggling attacks.
// Rejects requests that have both Transfer-Encoding and Content-Length headers.
func checkRequestSmuggling(req *http.Request) error {
	te := req.Header.Get("Transfer-Encoding")
	hasContentLength := req.Header.Get("Content-Length") != "" || req.ContentLength > 0

	if te != "" && hasContentLength {
		return ErrRequestSmuggling
	}

	// Check for obsolete line folding in headers
	for name, values := range req.Header {
		for _, v := range values {
			if hasObsoleteLineFolding(v) {
				return fmt.Errorf("obsolete line folding in header %s", name)
			}
		}
	}

	return nil
}

// hasObsoleteLineFolding checks for CR/LF followed by space/tab in header values.
func hasObsoleteLineFolding(s string) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '\r' || s[i] == '\n' {
			if i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
				return true
			}
		}
	}
	return false
}

// credentialRedactRe matches common credential patterns for log sanitization.
var credentialRedactRe = regexp.MustCompile(`(?i)(key|token|secret|password|bearer|authorization|api[_-]?key)[=:\s]+\S+`)

// sanitizeForLog redacts potential credentials from log messages.
func sanitizeForLog(s string) string {
	return credentialRedactRe.ReplaceAllString(s, "$1=[REDACTED]")
}

// validateHostForSSRF checks if a request host resolves to a private IP.
// Returns nil if safe, error if blocked.
func validateHostForSSRF(host string) error {
	hostname := normalizeHost(host)
	if hostname == "" {
		return fmt.Errorf("empty host")
	}

	if ip := net.ParseIP(hostname); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("%w: %s", ErrSSRFBlocked, ip.String())
		}
		return nil
	}

	// Resolve the hostname
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// DNS failure could be SSRF evasion: attacker crafts hostname that fails
		// here but resolves differently at client OS level. Fail closed.
		return fmt.Errorf("DNS lookup failed for %s: %w", hostname, err)
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("%w: %s resolves to %s", ErrSSRFBlocked, hostname, ip.String())
		}
	}

	return nil
}
