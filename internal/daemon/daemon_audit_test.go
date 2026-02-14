package daemon

import (
	"testing"

	"claw-wrap/internal/config"
)

func TestAuditConfigChanged_NilConfigSafety(t *testing.T) {
	withAudit := &config.Config{
		Audit: &config.AuditConfig{
			Enabled: true,
			File:    "/tmp/audit.log",
		},
	}

	if auditConfigChanged(nil, nil) {
		t.Fatal("expected no change when both configs are nil")
	}

	if !auditConfigChanged(nil, withAudit) {
		t.Fatal("expected change when old config is nil and new config is non-nil")
	}

	if !auditConfigChanged(withAudit, nil) {
		t.Fatal("expected change when old config is non-nil and new config is nil")
	}
}
