package daemon

import (
	"os"
	"testing"
)

func TestParseAuthFileMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    os.FileMode
		wantErr bool
	}{
		{name: "0600", input: "0600", want: 0o600},
		{name: "0640", input: "0640", want: 0o640},
		{name: "invalid", input: "0666", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAuthFileMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseAuthFileMode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got.Perm() != tt.want {
				t.Fatalf("ParseAuthFileMode() = %04o, want %04o", got.Perm(), tt.want)
			}
		})
	}
}

func TestParseSocketFileMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    os.FileMode
		wantErr bool
	}{
		{name: "0600", input: "0600", want: 0o600},
		{name: "0660", input: "0660", want: 0o660},
		{name: "invalid", input: "0640", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSocketFileMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSocketFileMode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got.Perm() != tt.want {
				t.Fatalf("ParseSocketFileMode() = %04o, want %04o", got.Perm(), tt.want)
			}
		})
	}
}

func TestDaemonRunRejectsInvalidRuntimeOptions(t *testing.T) {
	d := New(WithRuntimeGID(-2))
	if err := d.Run(); err == nil {
		t.Fatal("Run() should fail for invalid runtime gid")
	}

	d = New(WithAuthFileMode(0o666))
	if err := d.Run(); err == nil {
		t.Fatal("Run() should fail for invalid auth mode")
	}

	d = New(WithSocketFileMode(0o640))
	if err := d.Run(); err == nil {
		t.Fatal("Run() should fail for invalid socket mode")
	}
}

func TestRuntimeDirMode(t *testing.T) {
	d := New()
	if got := d.runtimeDirMode(); got != 0o700 {
		t.Fatalf("runtimeDirMode() = %04o, want 0700", got)
	}

	d = New(WithRuntimeGID(2000))
	if got := d.runtimeDirMode(); got != 0o750 {
		t.Fatalf("runtimeDirMode() = %04o, want 0750", got)
	}
}
