package provider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSecretFileCreatesExpectedMode(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "secret.json")

	if err := WriteSecretFile(filePath, []byte(`{"token":"value"}`)); err != nil {
		t.Fatalf("WriteSecretFile() error = %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}

	if got := info.Mode().Perm(); got != SecretFileMode {
		t.Fatalf("file mode = %#o, want %#o", got, SecretFileMode)
	}
}

func TestWriteSecretFileResetsExistingMode(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "secret.json")

	if err := os.WriteFile(filePath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() setup error = %v", err)
	}

	if err := os.Chmod(filePath, 0o600); err != nil {
		t.Fatalf("os.Chmod() setup error = %v", err)
	}

	if err := WriteSecretFile(filePath, []byte(`{"token":"updated"}`)); err != nil {
		t.Fatalf("WriteSecretFile() error = %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}

	if got := info.Mode().Perm(); got != SecretFileMode {
		t.Fatalf("file mode = %#o, want %#o", got, SecretFileMode)
	}
}
