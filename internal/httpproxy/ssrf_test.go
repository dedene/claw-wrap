package httpproxy

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestSSRFControl_BlocksPrivateIPs(t *testing.T) {
	tests := []struct {
		name    string
		network string
		address string
		wantErr bool
		errMsg  string
	}{
		// Private IPv4 ranges - should block
		{"loopback", "tcp", "127.0.0.1:80", true, "private IP blocked"},
		{"private 10.x", "tcp", "10.0.0.1:443", true, "private IP blocked"},
		{"private 172.16.x", "tcp", "172.16.0.1:80", true, "private IP blocked"},
		{"private 192.168.x", "tcp", "192.168.1.1:8080", true, "private IP blocked"},
		{"link-local", "tcp", "169.254.1.1:80", true, "private IP blocked"},
		{"carrier-grade NAT", "tcp", "100.64.0.1:80", true, "private IP blocked"},

		// Private IPv6 ranges - should block
		{"ipv6 loopback", "tcp6", "[::1]:80", true, "private IP blocked"},
		{"ipv6 link-local", "tcp6", "[fe80::1]:80", true, "private IP blocked"},
		{"ipv6 unique-local", "tcp6", "[fc00::1]:80", true, "private IP blocked"},

		// Public IPs - should allow
		{"public ipv4", "tcp", "8.8.8.8:443", false, ""},
		{"public ipv4 2", "tcp", "1.1.1.1:80", false, ""},
		{"public ipv6", "tcp6", "[2001:4860:4860::8888]:443", false, ""},

		// Invalid network types - should block
		{"udp blocked", "udp", "8.8.8.8:53", true, "unsupported network"},
		{"unix blocked", "unix", "/tmp/sock:0", true, "unsupported network"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ssrfControl(tt.network, tt.address, nil)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ssrfControl(%s, %s) expected error, got nil", tt.network, tt.address)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ssrfControl(%s, %s) error = %v, want to contain %q", tt.network, tt.address, err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ssrfControl(%s, %s) unexpected error = %v", tt.network, tt.address, err)
				}
			}
		})
	}
}

func TestSSRFControl_ReturnsCorrectErrorType(t *testing.T) {
	err := ssrfControl("tcp", "127.0.0.1:80", nil)
	if err == nil {
		t.Fatal("expected error for private IP")
	}
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Errorf("error should wrap ErrSSRFBlocked, got: %v", err)
	}
}

func TestSSRFControl_InvalidAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{"no port", "8.8.8.8"},
		{"empty", ""},
		{"garbage", "not-an-address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ssrfControl("tcp", tt.address, nil)
			if err == nil {
				t.Errorf("ssrfControl(tcp, %q) expected error for invalid address", tt.address)
			}
		})
	}
}

func TestSafeDialer_HasControlCallback(t *testing.T) {
	d := safeDialer()
	if d.Control == nil {
		t.Error("safeDialer().Control should not be nil")
	}
	if d.Timeout <= 0 {
		t.Error("safeDialer().Timeout should be positive")
	}
}

func TestSafeTransport_HasDialContext(t *testing.T) {
	tr := safeTransport()
	if tr.DialContext == nil {
		t.Error("safeTransport().DialContext should not be nil")
	}
	if tr.TLSClientConfig == nil {
		t.Error("safeTransport().TLSClientConfig should not be nil")
	}
	if tr.TLSClientConfig.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Error("safeTransport() should enforce TLS 1.2 minimum")
	}
}

func TestSafeConnectDial_ReturnsFunction(t *testing.T) {
	dial := safeConnectDial()
	if dial == nil {
		t.Error("safeConnectDial() should not return nil")
	}
}

func TestSafeDialer_IntegrationBlocksPrivateIP(t *testing.T) {
	// This test verifies the complete flow through the dialer
	d := safeDialer()

	// Attempt to dial a private IP - should fail due to Control callback
	conn, err := d.Dial("tcp", "127.0.0.1:80")
	if conn != nil {
		conn.Close()
		t.Error("expected connection to private IP to fail")
	}
	if err == nil {
		t.Error("expected error when dialing private IP")
	}
	if !strings.Contains(err.Error(), "SSRF") && !strings.Contains(err.Error(), "blocked") {
		// The error message varies by platform, but should indicate blocking
		t.Logf("error: %v", err)
	}
}

func TestSafeDialer_IntegrationAllowsPublicIP(t *testing.T) {
	// Skip if no network
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	// Resolve a known public host to get a real IP
	ips, err := net.LookupIP("example.com")
	if err != nil {
		t.Skipf("DNS lookup failed: %v", err)
	}

	var publicIP net.IP
	for _, ip := range ips {
		if !isPrivateIP(ip) {
			publicIP = ip
			break
		}
	}
	if publicIP == nil {
		t.Skip("no public IP found for example.com")
	}

	// The Control callback should allow this IP
	err = ssrfControl("tcp", publicIP.String()+":80", nil)
	if err != nil {
		t.Errorf("ssrfControl should allow public IP %s: %v", publicIP, err)
	}
}
