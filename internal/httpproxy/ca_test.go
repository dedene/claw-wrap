package httpproxy

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
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
