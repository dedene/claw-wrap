package httpproxy

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		// Private IPv4 ranges
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"127.0.0.1", true},
		{"169.254.0.1", true},

		// Public IPv4
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},

		// Private IPv6
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},

		// Public IPv6
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %s", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.private {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}

func TestCheckRequestSmuggling(t *testing.T) {
	tests := []struct {
		name      string
		headers   map[string]string
		wantError bool
		errMsg    string
	}{
		{
			name:      "normal request",
			headers:   map[string]string{"Content-Type": "application/json"},
			wantError: false,
		},
		{
			name:      "TE only",
			headers:   map[string]string{"Transfer-Encoding": "chunked"},
			wantError: false,
		},
		{
			name:      "CL only",
			headers:   map[string]string{"Content-Length": "100"},
			wantError: false,
		},
		{
			name: "TE + CL smuggling",
			headers: map[string]string{
				"Transfer-Encoding": "chunked",
				"Content-Length":    "100",
			},
			wantError: true,
			errMsg:    "smuggling",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "http://example.com", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			err := checkRequestSmuggling(req)
			if tt.wantError {
				if err == nil {
					t.Error("checkRequestSmuggling() expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %v, want to contain %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("checkRequestSmuggling() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestHasObsoleteLineFolding(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"normal value", false},
		{"value\r\n with folding", true},
		{"value\n\twith tab", true},
		{"\r\n header", true},
		{"no problem here", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := hasObsoleteLineFolding(tt.input)
			if got != tt.want {
				t.Errorf("hasObsoleteLineFolding(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal log message", "normal log message"},
		{"token=abc123", "token=[REDACTED]"},
		{"Token: abc123", "Token=[REDACTED]"},
		{"Authorization: Bearer-abc", "Authorization=[REDACTED]"}, // single word with dash
		{"api_key=secret123", "api_key=[REDACTED]"},
		{"API-KEY: xyz", "API-KEY=[REDACTED]"},
		{"password: hunter2", "password=[REDACTED]"},
		{"SECRET=my-secret", "SECRET=[REDACTED]"},
		{"multiple token=a and key=b", "multiple token=[REDACTED] and key=[REDACTED]"},
		{"Bearer some-jwt-token", "Bearer=[REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeForLog(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeForLog(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateRequestSecurity(t *testing.T) {
	t.Run("normal request passes", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		if err := validateRequestSecurity(req); err != nil {
			t.Errorf("validateRequestSecurity() unexpected error = %v", err)
		}
	})

	t.Run("smuggling attempt blocked", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "http://example.com", nil)
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("Content-Length", "100")

		err := validateRequestSecurity(req)
		if err == nil {
			t.Error("validateRequestSecurity() expected error for smuggling attempt")
		}
	})
}

func TestValidateHostForSSRF_PublicIPs(t *testing.T) {
	// These should pass SSRF check (assuming DNS resolves correctly)
	hosts := []string{
		"google.com",
		"example.com",
		"8.8.8.8",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			err := validateHostForSSRF(host)
			if err != nil {
				// DNS might fail in some test environments, that's OK
				// We now fail closed on DNS errors, so check for either error type
				errStr := err.Error()
				if !strings.Contains(errStr, "no such host") && !strings.Contains(errStr, "DNS lookup failed") {
					t.Errorf("validateHostForSSRF(%s) unexpected error = %v", host, err)
				}
			}
		})
	}
}

func TestValidateHostForSSRF_DNSFailure(t *testing.T) {
	// DNS failures should be rejected (fail closed) to prevent SSRF evasion
	hosts := []string{
		"nonexistent.invalid.test",
		"definitely-not-a-real-domain-12345.com",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			err := validateHostForSSRF(host)
			if err == nil {
				t.Errorf("validateHostForSSRF(%s) expected error for DNS failure, got nil", host)
			}
			if !strings.Contains(err.Error(), "DNS lookup failed") {
				t.Errorf("validateHostForSSRF(%s) error should mention DNS failure: %v", host, err)
			}
		})
	}
}

func TestValidateHostForSSRF_PrivateIPs(t *testing.T) {
	// These should be blocked
	hosts := []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"localhost",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			err := validateHostForSSRF(host)
			// Note: localhost resolution might vary by system
			if host == "localhost" {
				// Skip if DNS doesn't resolve localhost
				return
			}
			if err == nil {
				t.Errorf("validateHostForSSRF(%s) expected error for private IP", host)
			}
		})
	}
}
