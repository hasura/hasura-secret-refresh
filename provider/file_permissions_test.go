package provider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSecretFileCreatesFileWithExpectedMode(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "secret.json")

	if err := WriteSecretFile(filePath, []byte(`{"token":"value"}`)); err != nil {
		t.Fatalf("WriteSecretFile returned error: %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}

	if got := info.Mode().Perm(); got != SecretFileMode {
		t.Fatalf("expected mode %04o, got %04o", SecretFileMode, got)
	}
}

func TestWriteSecretFileNormalizesExistingMode(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "secret.json")

	if err := os.WriteFile(filePath, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	if err := os.Chmod(filePath, 0o600); err != nil {
		t.Fatalf("Chmod returned error: %v", err)
	}

	if err := WriteSecretFile(filePath, []byte("new")); err != nil {
		t.Fatalf("WriteSecretFile returned error: %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}

	if got := info.Mode().Perm(); got != SecretFileMode {
		t.Fatalf("expected mode %04o, got %04o", SecretFileMode, got)
	}
}
