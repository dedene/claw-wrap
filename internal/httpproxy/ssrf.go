package httpproxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// safeDialer returns a net.Dialer with a Control callback that blocks connections
// to private/reserved IP addresses. The Control callback runs AFTER DNS resolution
// but BEFORE the connection is established, preventing DNS rebinding attacks.
func safeDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   ssrfControl,
	}
}

// ssrfControl is a net.Dialer Control callback that validates the resolved IP
// address before allowing a connection. This prevents SSRF attacks including
// DNS rebinding, since validation occurs after DNS resolution.
func ssrfControl(network, address string, _ syscall.RawConn) error {
	// Only allow TCP connections
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return fmt.Errorf("unsupported network type: %s", network)
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", host)
	}

	if isPrivateIP(ip) {
		return fmt.Errorf("%w: %s", ErrSSRFBlocked, ip)
	}

	return nil
}

// safeTransport returns an http.Transport configured with the safe dialer.
// This should be used for goproxy's Tr field.
func safeTransport() *http.Transport {
	dialer := safeDialer()
	return &http.Transport{
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}
}

// safeConnectDial returns a dial function for goproxy's ConnectDial field.
// This is used for HTTPS CONNECT tunneling.
func safeConnectDial() func(network, addr string) (net.Conn, error) {
	dialer := safeDialer()
	return dialer.Dial
}
