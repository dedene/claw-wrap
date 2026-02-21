package httpproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claw-wrap/internal/config"
)

func TestNewCAManager(t *testing.T) {
	cfg := config.CAConfig{
		Path:         "/tmp/test-ca",
		ValidityDays: 30,
		Organization: "test-org",
	}

	mgr := NewCAManager(cfg)
	if mgr == nil {
		t.Fatal("NewCAManager returned nil")
	}
	if mgr.certPath != "/tmp/test-ca/ca.crt" {
		t.Errorf("certPath = %q, want /tmp/test-ca/ca.crt", mgr.certPath)
	}
	if mgr.keyPath != "/tmp/test-ca/ca.key" {
		t.Errorf("keyPath = %q, want /tmp/test-ca/ca.key", mgr.keyPath)
	}
}

func TestNewCAManager_DefaultPath(t *testing.T) {
	cfg := config.CAConfig{} // Empty path

	mgr := NewCAManager(cfg)
	if mgr == nil {
		t.Fatal("NewCAManager returned nil")
	}
	// Should use default path
	if !filepath.IsAbs(mgr.certPath) {
		t.Errorf("certPath should be absolute, got %q", mgr.certPath)
	}
}

func TestCAManager_EnsureCA_GeneratesNew(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.CAConfig{
		Path:         tmpDir,
		ValidityDays: 30,
		Organization: "test-org",
	}

	mgr := NewCAManager(cfg)

	cert, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}
	if cert == nil {
		t.Fatal("EnsureCA returned nil cert")
	}

	// Verify files created
	if _, err := os.Stat(filepath.Join(tmpDir, "ca.crt")); err != nil {
		t.Errorf("ca.crt not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "ca.key")); err != nil {
		t.Errorf("ca.key not created: %v", err)
	}

	// Verify key permissions
	keyInfo, err := os.Stat(filepath.Join(tmpDir, "ca.key"))
	if err != nil {
		t.Fatalf("stat ca.key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("ca.key permissions = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestCAManager_EnsureCA_LoadsExisting(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.CAConfig{
		Path:         tmpDir,
		ValidityDays: 365, // Use 365 days to avoid rotation trigger (30-day buffer)
		Organization: "test-org",
	}

	mgr := NewCAManager(cfg)

	// First call generates
	cert1, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("first EnsureCA error: %v", err)
	}

	// Second call loads existing
	mgr2 := NewCAManager(cfg)
	cert2, err := mgr2.EnsureCA()
	if err != nil {
		t.Fatalf("second EnsureCA error: %v", err)
	}

	// Should be the same certificate
	if len(cert1.Certificate) == 0 || len(cert2.Certificate) == 0 {
		t.Fatal("empty certificate chain")
	}
	x509Cert1, _ := x509.ParseCertificate(cert1.Certificate[0])
	x509Cert2, _ := x509.ParseCertificate(cert2.Certificate[0])

	if x509Cert1.SerialNumber.Cmp(x509Cert2.SerialNumber) != 0 {
		t.Error("serial numbers differ, CA was regenerated")
	}
}

func TestCAManager_CertificateProperties(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.CAConfig{
		Path:         tmpDir,
		ValidityDays: 90,
		Organization: "My Test Org",
	}

	mgr := NewCAManager(cfg)
	cert, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	// Check organization
	if len(x509Cert.Subject.Organization) != 1 || x509Cert.Subject.Organization[0] != "My Test Org" {
		t.Errorf("organization = %v, want [My Test Org]", x509Cert.Subject.Organization)
	}

	// Check CN
	if x509Cert.Subject.CommonName != "My Test Org CA" {
		t.Errorf("CN = %q, want \"My Test Org CA\"", x509Cert.Subject.CommonName)
	}

	// Check validity period (~90 days)
	expectedExpiry := time.Now().AddDate(0, 0, 90)
	diff := x509Cert.NotAfter.Sub(expectedExpiry)
	if diff < -time.Hour || diff > time.Hour {
		t.Errorf("NotAfter = %v, want ~%v", x509Cert.NotAfter, expectedExpiry)
	}

	// Check CA flag
	if !x509Cert.IsCA {
		t.Error("IsCA = false, want true")
	}

	// Check key usage
	if x509Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("missing KeyUsageCertSign")
	}
}

func TestCAManager_NeedsRotation_Fresh(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.CAConfig{
		Path:         tmpDir,
		ValidityDays: 365,
	}

	mgr := NewCAManager(cfg)
	_, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}

	if mgr.NeedsRotation() {
		t.Error("fresh CA should not need rotation")
	}
}

func TestCAManager_NeedsRotation_NoCert(t *testing.T) {
	cfg := config.CAConfig{
		Path: t.TempDir(),
	}

	mgr := NewCAManager(cfg)
	// Don't call EnsureCA

	if !mgr.NeedsRotation() {
		t.Error("manager with no cert should need rotation")
	}
}

func TestCAManager_CertPath(t *testing.T) {
	cfg := config.CAConfig{
		Path: "/custom/path",
	}

	mgr := NewCAManager(cfg)
	if mgr.CertPath() != "/custom/path/ca.crt" {
		t.Errorf("CertPath = %q, want /custom/path/ca.crt", mgr.CertPath())
	}
}

func TestCAManager_Certificate_BeforeEnsure(t *testing.T) {
	cfg := config.CAConfig{
		Path: t.TempDir(),
	}

	mgr := NewCAManager(cfg)
	if mgr.Certificate() != nil {
		t.Error("Certificate before EnsureCA should be nil")
	}
}

func TestCAManager_Certificate_AfterEnsure(t *testing.T) {
	cfg := config.CAConfig{
		Path: t.TempDir(),
	}

	mgr := NewCAManager(cfg)
	_, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}

	cert := mgr.Certificate()
	if cert == nil {
		t.Error("Certificate after EnsureCA should not be nil")
	}
}

func TestCAManager_ValidCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.CAConfig{
		Path: tmpDir,
	}

	mgr := NewCAManager(cfg)
	_, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}

	// Load and verify it's a valid TLS certificate
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(tmpDir, "ca.crt"),
		filepath.Join(tmpDir, "ca.key"),
	)
	if err != nil {
		t.Fatalf("LoadX509KeyPair error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("empty certificate chain")
	}
}

// --- External CA mode tests ---

func TestCAManager_External_FailsOnMissingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.CAConfig{
		Path:     tmpDir,
		External: true,
	}

	mgr := NewCAManager(cfg)
	_, err := mgr.EnsureCA()
	if err == nil {
		t.Error("expected error when external CA files missing")
	}
	// Should mention "external CA not found"
	if !strings.Contains(err.Error(), "external CA not found") {
		t.Errorf("error message should mention 'external CA not found': %v", err)
	}
}

func TestCAManager_External_LoadsExistingCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid CA cert/key
	createTestCA(t, tmpDir, "ca.crt", "ca.key")

	cfg := config.CAConfig{
		Path:     tmpDir,
		External: true,
	}

	mgr := NewCAManager(cfg)
	cert, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}
	if cert == nil {
		t.Error("expected non-nil certificate")
	}
	if !mgr.External() {
		t.Error("External() should return true")
	}
}

func TestCAManager_External_CustomFilenames(t *testing.T) {
	tmpDir := t.TempDir()

	// Create CA with custom filenames (like cert-manager)
	createTestCA(t, tmpDir, "tls.crt", "tls.key")

	cfg := config.CAConfig{
		Path:     tmpDir,
		CertFile: "tls.crt",
		KeyFile:  "tls.key",
		External: true,
	}

	mgr := NewCAManager(cfg)
	if mgr.CertPath() != filepath.Join(tmpDir, "tls.crt") {
		t.Errorf("CertPath = %q, want %q", mgr.CertPath(), filepath.Join(tmpDir, "tls.crt"))
	}

	cert, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}
	if cert == nil {
		t.Error("expected non-nil certificate")
	}
}

func TestCAManager_External_SkipsPermissionCheck(t *testing.T) {
	tmpDir := t.TempDir()

	// Create CA with 0644 permissions (like k8s secrets)
	createTestCAWithPerms(t, tmpDir, "ca.crt", "ca.key", 0644)

	// External mode should accept 0644
	cfg := config.CAConfig{
		Path:     tmpDir,
		External: true,
	}
	mgr := NewCAManager(cfg)
	cert, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("external mode should accept 0644 perms: %v", err)
	}
	if cert == nil {
		t.Error("expected non-nil certificate")
	}
}

func TestCAManager_SelfManaged_RegeneratesOnInsecurePerms(t *testing.T) {
	tmpDir := t.TempDir()

	// Create CA with 0644 permissions
	createTestCAWithPerms(t, tmpDir, "ca.crt", "ca.key", 0644)

	// Get original serial
	origCert, _ := tls.LoadX509KeyPair(
		filepath.Join(tmpDir, "ca.crt"),
		filepath.Join(tmpDir, "ca.key"),
	)
	origX509, _ := x509.ParseCertificate(origCert.Certificate[0])
	origSerial := origX509.SerialNumber

	// Self-managed mode should regenerate CA (not use the insecure one)
	cfg := config.CAConfig{
		Path:     tmpDir,
		External: false,
	}
	mgr := NewCAManager(cfg)
	cert, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}

	// Should have generated a new CA with different serial
	newX509, _ := x509.ParseCertificate(cert.Certificate[0])
	if origSerial.Cmp(newX509.SerialNumber) == 0 {
		t.Error("expected new CA to be generated due to insecure permissions")
	}

	// New key should have 0600 permissions
	keyInfo, err := os.Stat(filepath.Join(tmpDir, "ca.key"))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("regenerated key perms = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestCAManager_External_ValidatesCAFlag(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a non-CA certificate (end-entity)
	createTestNonCACert(t, tmpDir, "ca.crt", "ca.key")

	cfg := config.CAConfig{
		Path:     tmpDir,
		External: true,
	}
	mgr := NewCAManager(cfg)
	_, err := mgr.EnsureCA()
	if err == nil {
		t.Error("expected error for non-CA certificate")
	}
	if !strings.Contains(err.Error(), "IsCA=false") {
		t.Errorf("error should mention IsCA: %v", err)
	}
}

// --- Watcher tests ---

func TestCAManager_Watcher_StartsOnlyInExternalMode(t *testing.T) {
	tmpDir := t.TempDir()
	createTestCA(t, tmpDir, "ca.crt", "ca.key")

	// Self-managed mode: watcher should not start
	cfg := config.CAConfig{
		Path:     tmpDir,
		External: false,
	}
	mgr := NewCAManager(cfg)
	if err := mgr.StartWatcher(); err != nil {
		t.Fatalf("StartWatcher error: %v", err)
	}
	// Should be a no-op, no watcher created
	mgr.StopWatcher() // Should not panic

	// External mode: watcher should start
	cfg.External = true
	mgr2 := NewCAManager(cfg)
	_, err := mgr2.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}
	if err := mgr2.StartWatcher(); err != nil {
		t.Fatalf("StartWatcher error: %v", err)
	}
	mgr2.StopWatcher()
}

func TestCAManager_Watcher_ReloadsOnChange(t *testing.T) {
	tmpDir := t.TempDir()
	createTestCA(t, tmpDir, "ca.crt", "ca.key")

	cfg := config.CAConfig{
		Path:     tmpDir,
		External: true,
	}
	mgr := NewCAManager(cfg)
	cert1, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}

	if err := mgr.StartWatcher(); err != nil {
		t.Fatalf("StartWatcher error: %v", err)
	}
	defer mgr.StopWatcher()

	// Get original serial
	x509Cert1, _ := x509.ParseCertificate(cert1.Certificate[0])
	origSerial := x509Cert1.SerialNumber

	// Replace with new CA
	createTestCA(t, tmpDir, "ca.crt", "ca.key")

	// Poll for certificate change with timeout (avoid flaky fixed sleep)
	deadline := time.Now().Add(2 * time.Second)
	var reloaded bool
	for time.Now().Before(deadline) {
		cert2 := mgr.Certificate()
		if cert2 != nil {
			x509Cert2, _ := x509.ParseCertificate(cert2.Certificate[0])
			if origSerial.Cmp(x509Cert2.SerialNumber) != 0 {
				reloaded = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !reloaded {
		t.Error("certificate serial unchanged after 2s, watcher may not have reloaded")
	}
}

func TestCAManager_Watcher_StopsCleanly(t *testing.T) {
	tmpDir := t.TempDir()
	createTestCA(t, tmpDir, "ca.crt", "ca.key")

	cfg := config.CAConfig{
		Path:     tmpDir,
		External: true,
	}
	mgr := NewCAManager(cfg)
	_, err := mgr.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA error: %v", err)
	}

	if err := mgr.StartWatcher(); err != nil {
		t.Fatalf("StartWatcher error: %v", err)
	}

	// Stop should not panic or hang
	mgr.StopWatcher()

	// Double stop should be safe
	mgr.StopWatcher()
}

func TestCAManager_ValidatesExpiry(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an expired certificate
	createExpiredTestCA(t, tmpDir, "ca.crt", "ca.key")

	cfg := config.CAConfig{
		Path:     tmpDir,
		External: true,
	}
	mgr := NewCAManager(cfg)
	_, err := mgr.EnsureCA()
	if err == nil {
		t.Fatal("EnsureCA should fail on expired certificate")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention 'expired', got: %v", err)
	}
}

func TestCAManager_ValidatesNotYetValid(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a certificate that's not yet valid
	createFutureTestCA(t, tmpDir, "ca.crt", "ca.key")

	cfg := config.CAConfig{
		Path:     tmpDir,
		External: true,
	}
	mgr := NewCAManager(cfg)
	_, err := mgr.EnsureCA()
	if err == nil {
		t.Fatal("EnsureCA should fail on not-yet-valid certificate")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("error should mention 'not yet valid', got: %v", err)
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/normal/path/ca.crt", "/normal/path/ca.crt"},
		{"/path/with\nnewline", "/path/with?newline"},
		{"/path/with\ttab", "/path/with?tab"},
		{"/path/with\x00nul", "/path/with?nul"},
		{"/path/with\x7fdel", "/path/with?del"},
		{"/path\r\n/crlf", "/path??/crlf"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizePath(tt.input)
			if got != tt.want {
				t.Errorf("sanitizePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Helper functions ---

func createTestCA(t *testing.T, dir, certFile, keyFile string) {
	t.Helper()
	createTestCAWithPerms(t, dir, certFile, keyFile, 0600)
}

func createTestCAWithPerms(t *testing.T, dir, certFile, keyFile string, keyPerm os.FileMode) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Test CA"}, CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, keyPerm); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func createTestNonCACert(t *testing.T, dir, certFile, keyFile string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Not A CA"}, CommonName: "End Entity"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false, // Not a CA!
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func createExpiredTestCA(t *testing.T, dir, certFile, keyFile string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	// Certificate that expired yesterday
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Test CA"}, CommonName: "Expired CA"},
		NotBefore:             time.Now().AddDate(0, 0, -30),
		NotAfter:              time.Now().AddDate(0, 0, -1), // Expired yesterday
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func createFutureTestCA(t *testing.T, dir, certFile, keyFile string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	// Certificate that starts tomorrow
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Test CA"}, CommonName: "Future CA"},
		NotBefore:             time.Now().AddDate(0, 0, 1), // Valid from tomorrow
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}
}
