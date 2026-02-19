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
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

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
	external bool // external management mode (cert-manager, k8s secrets, etc.)

	cert        *tls.Certificate
	certMu      sync.RWMutex      // protects cert during hot-reload
	watcher     *fsnotify.Watcher // file watcher for external mode
	stopCh      chan struct{}     // stop signal for watcher goroutine
	watcherWg   sync.WaitGroup    // wait for watcher goroutine to exit
	stopOnce    sync.Once         // ensure StopWatcher only runs once
	watcherInit bool              // true if watcher was started
}

// NewCAManager creates a new CA manager with the given configuration.
func NewCAManager(cfg config.CAConfig) *CAManager {
	path := cfg.Path
	if path == "" {
		path = DefaultCAPath()
	}

	// Use custom filenames or defaults
	certFile := cfg.CertFile
	if certFile == "" {
		certFile = "ca.crt"
	}
	keyFile := cfg.KeyFile
	if keyFile == "" {
		keyFile = "ca.key"
	}

	return &CAManager{
		certPath: filepath.Join(path, certFile),
		keyPath:  filepath.Join(path, keyFile),
		config:   cfg,
		external: cfg.External,
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
		// Validate it's actually a CA certificate
		if err := m.validateCA(cert); err != nil {
			return nil, fmt.Errorf("CA validation failed: %w", err)
		}

		// Check if rotation is needed (only for self-managed CAs)
		if !m.external && m.needsRotation(cert) {
			log.Printf("[INFO] CA certificate expires soon, regenerating")
			return m.generateAndSaveCA()
		}

		m.certMu.Lock()
		m.cert = cert
		m.certMu.Unlock()

		if m.external {
			log.Printf("[INFO] Using external CA from %s", sanitizePath(m.certPath))
		}
		return cert, nil
	}

	// External mode: fail if CA files don't exist
	if m.external {
		return nil, fmt.Errorf("external CA not found at %s: %w (hint: ensure cert-manager secret is mounted)", sanitizePath(m.certPath), err)
	}

	// Generate new CA
	log.Printf("[INFO] Generating new CA certificate")
	return m.generateAndSaveCA()
}

// validateCA checks that the loaded certificate is actually a CA.
func (m *CAManager) validateCA(cert *tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("certificate chain is empty")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	if !x509Cert.IsCA {
		return fmt.Errorf("certificate is not a CA (IsCA=false)")
	}

	if x509Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate lacks KeyUsageCertSign")
	}

	// Check certificate expiry
	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid (NotBefore: %s)", x509Cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(x509Cert.NotAfter) {
		return fmt.Errorf("certificate expired on %s", x509Cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

// Certificate returns the loaded CA certificate (thread-safe).
func (m *CAManager) Certificate() *tls.Certificate {
	m.certMu.RLock()
	defer m.certMu.RUnlock()
	return m.cert
}

// CertPath returns the path to the CA certificate file.
func (m *CAManager) CertPath() string {
	return m.certPath
}

// NeedsRotation checks if the CA certificate needs rotation.
func (m *CAManager) NeedsRotation() bool {
	m.certMu.RLock()
	cert := m.cert
	m.certMu.RUnlock()

	if cert == nil {
		return true
	}
	return m.needsRotation(cert)
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
	// Skip permission check for external mode (k8s secrets mount with 0644)
	if !m.external {
		info, err := os.Stat(m.keyPath)
		if err != nil {
			return nil, err
		}
		perm := info.Mode().Perm()
		if perm > 0o600 {
			return nil, fmt.Errorf("CA key has insecure permissions %04o (want 0600 or stricter)", perm)
		}
	} else {
		log.Printf("[INFO] External CA mode: key permission check relaxed (k8s compat)")
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
	// Ensure permissions are correct even if file existed with different perms
	if err := os.Chmod(m.keyPath, 0600); err != nil {
		os.Remove(m.certPath)
		os.Remove(m.keyPath)
		return nil, fmt.Errorf("chmod key: %w", err)
	}

	log.Printf("[INFO] CA certificate saved to %s (valid for %d days)", sanitizePath(m.certPath), validityDays)

	// Load the saved certificate
	cert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load generated CA: %w", err)
	}

	m.certMu.Lock()
	m.cert = &cert
	m.certMu.Unlock()
	return &cert, nil
}

// StartWatcher starts watching CA files for changes (external mode only).
// Returns nil if not in external mode.
func (m *CAManager) StartWatcher() error {
	if !m.external {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}

	// Watch the directory containing the cert (handles k8s secret updates)
	dir := filepath.Dir(m.certPath)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("watch directory %s: %w", sanitizePath(dir), err)
	}

	m.watcher = watcher
	m.stopCh = make(chan struct{})
	m.watcherInit = true
	m.stopOnce = sync.Once{} // Reset for potential restart

	m.watcherWg.Add(1)
	go m.watchLoop()

	log.Printf("[INFO] CA file watcher started for %s", sanitizePath(dir))
	return nil
}

// StopWatcher stops the file watcher. Safe to call multiple times.
func (m *CAManager) StopWatcher() {
	if !m.watcherInit {
		return
	}

	m.stopOnce.Do(func() {
		if m.stopCh != nil {
			close(m.stopCh)
		}
		// Wait for watchLoop to exit before closing watcher
		m.watcherWg.Wait()

		if m.watcher != nil {
			m.watcher.Close()
			m.watcher = nil
		}
		m.stopCh = nil
		m.watcherInit = false
	})
}

func (m *CAManager) watchLoop() {
	defer m.watcherWg.Done()

	certFile := filepath.Base(m.certPath)
	keyFile := filepath.Base(m.keyPath)

	for {
		select {
		case <-m.stopCh:
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			// Check if this event is relevant:
			// - Direct file changes (tls.crt, tls.key, ca.crt, ca.key)
			// - k8s secret symlink updates (..data symlink change)
			eventFile := filepath.Base(event.Name)
			isRelevantFile := eventFile == certFile || eventFile == keyFile
			isK8sSymlink := eventFile == "..data" // k8s atomic secret update

			if !isRelevantFile && !isK8sSymlink {
				continue
			}

			// React to write, create, or chmod events
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Chmod) == 0 {
				continue
			}

			// Reload the certificate
			if err := m.reloadCA(); err != nil {
				log.Printf("[WARN] CA reload failed: %v", err)
			} else {
				log.Printf("[INFO] CA certificate reloaded")
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[WARN] CA watcher error: %v", err)
		}
	}
}

func (m *CAManager) reloadCA() error {
	cert, err := m.loadCA()
	if err != nil {
		return err
	}

	if err := m.validateCA(cert); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	m.certMu.Lock()
	m.cert = cert
	m.certMu.Unlock()

	return nil
}

// External returns whether this CA is externally managed.
func (m *CAManager) External() bool {
	return m.external
}

// sanitizePath removes control characters from a path for safe logging.
func sanitizePath(path string) string {
	var result []rune
	for _, r := range path {
		if r < 32 || r == 127 {
			result = append(result, '?')
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}
