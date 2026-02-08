// Package httpproxy implements CA certificate management for MITM proxy.
package httpproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"claw-wrap/internal/config"
	"claw-wrap/internal/paths"
)

const (
	// DefaultCAValidityDays is the default CA validity period.
	DefaultCAValidityDays = 365
	// DefaultCAOrganization is the default CA organization name.
	DefaultCAOrganization = "claw-wrap"
	// CAKeyBits is the RSA key size for the CA.
	CAKeyBits = 4096
	// RotationBuffer is days before expiry to trigger rotation.
	RotationBuffer = 30
)

// CAManager handles CA certificate generation and storage.
type CAManager struct {
	certPath string
	keyPath  string
	config   config.CAConfig

	cert *tls.Certificate
}

// NewCAManager creates a new CA manager with the given configuration.
func NewCAManager(cfg config.CAConfig) *CAManager {
	path := cfg.Path
	if path == "" {
		path = DefaultCAPath()
	}

	return &CAManager{
		certPath: filepath.Join(path, "ca.crt"),
		keyPath:  filepath.Join(path, "ca.key"),
		config:   cfg,
	}
}

// DefaultCAPath returns the default CA directory path.
func DefaultCAPath() string {
	return paths.CADir()
}

// EnsureCA loads or generates the CA certificate.
// Returns the loaded/generated certificate for use with goproxy.
func (m *CAManager) EnsureCA() (*tls.Certificate, error) {
	// Try to load existing CA
	cert, err := m.loadCA()
	if err == nil {
		// Check if rotation is needed
		if m.needsRotation(cert) {
			log.Printf("[INFO] CA certificate expires soon, regenerating")
			return m.generateAndSaveCA()
		}
		m.cert = cert
		return cert, nil
	}

	// Generate new CA
	log.Printf("[INFO] Generating new CA certificate")
	return m.generateAndSaveCA()
}

// Certificate returns the loaded CA certificate.
func (m *CAManager) Certificate() *tls.Certificate {
	return m.cert
}

// CertPath returns the path to the CA certificate file.
func (m *CAManager) CertPath() string {
	return m.certPath
}

// NeedsRotation checks if the CA certificate needs rotation.
func (m *CAManager) NeedsRotation() bool {
	if m.cert == nil {
		return true
	}
	return m.needsRotation(m.cert)
}

func (m *CAManager) needsRotation(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return true
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}

	// Rotate if expiring within RotationBuffer days
	rotationDate := time.Now().AddDate(0, 0, RotationBuffer)
	return x509Cert.NotAfter.Before(rotationDate)
}

func (m *CAManager) loadCA() (*tls.Certificate, error) {
	// Check key file permissions before loading (security: detect compromised keys)
	info, err := os.Stat(m.keyPath)
	if err != nil {
		return nil, err
	}
	perm := info.Mode().Perm()
	if perm > 0o600 {
		return nil, fmt.Errorf("CA key %s has insecure permissions %04o (want 0600 or stricter)", m.keyPath, perm)
	}

	cert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (m *CAManager) generateAndSaveCA() (*tls.Certificate, error) {
	// Ensure directory exists with secure permissions
	dir := filepath.Dir(m.certPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create CA directory: %w", err)
	}

	// Generate key
	key, err := rsa.GenerateKey(rand.Reader, CAKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	// Generate certificate
	validityDays := m.config.ValidityDays
	if validityDays <= 0 {
		validityDays = DefaultCAValidityDays
	}

	org := m.config.Organization
	if org == "" {
		org = DefaultCAOrganization
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   org + " CA",
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	// Save certificate (world-readable is OK for the public cert)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(m.certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("write certificate: %w", err)
	}

	// Save key with restrictive permissions
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(m.keyPath, keyPEM, 0600); err != nil {
		// Clean up cert if key write fails
		os.Remove(m.certPath)
		return nil, fmt.Errorf("write key: %w", err)
	}

	log.Printf("[INFO] CA certificate saved to %s (valid for %d days)", m.certPath, validityDays)

	// Load the saved certificate
	cert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load generated CA: %w", err)
	}

	m.cert = &cert
	return &cert, nil
}
