package hashicorp_vault

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	sharedprovider "github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

func validFileConfig(extra map[string]interface{}) map[string]interface{} {
	cfg := map[string]interface{}{
		"vault_addr":   "https://vault.example.com:8200",
		"auth":         validAuthMap(),
		"path_on_disk": "/tmp/secret.txt",
		"path":         "postgres/prod",
		"refresh":      60,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func TestCreateHashicorpVaultFile_MissingVaultAddr(t *testing.T) {
	cfg := validFileConfig(nil)
	delete(cfg, "vault_addr")
	_, err := CreateHashicorpVaultFile(cfg, zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "config not valid") {
		t.Errorf("expected config error, got: %v", err)
	}
}

func TestCreateHashicorpVaultFile_MissingPathOnDisk(t *testing.T) {
	cfg := validFileConfig(nil)
	delete(cfg, "path_on_disk")
	_, err := CreateHashicorpVaultFile(cfg, zerolog.Nop())
	if err == nil || err.Error() != "required configs not found" {
		t.Errorf("expected required configs error, got: %v", err)
	}
}

func TestCreateHashicorpVaultFile_InvalidPathOnDisk(t *testing.T) {
	cfg := validFileConfig(map[string]interface{}{"path_on_disk": 123})
	_, err := CreateHashicorpVaultFile(cfg, zerolog.Nop())
	if err == nil || err.Error() != "config not valid" {
		t.Errorf("expected config not valid, got: %v", err)
	}
}

func TestCreateHashicorpVaultFile_MissingPath(t *testing.T) {
	cfg := validFileConfig(nil)
	delete(cfg, "path")
	_, err := CreateHashicorpVaultFile(cfg, zerolog.Nop())
	if err == nil || err.Error() != "required configs not found" {
		t.Errorf("expected required configs error, got: %v", err)
	}
}

func TestCreateHashicorpVaultFile_MissingRefresh(t *testing.T) {
	cfg := validFileConfig(nil)
	delete(cfg, "refresh")
	_, err := CreateHashicorpVaultFile(cfg, zerolog.Nop())
	if err == nil || err.Error() != "required configs not found" {
		t.Errorf("expected required configs error, got: %v", err)
	}
}

func TestCreateHashicorpVaultFile_InvalidRefresh(t *testing.T) {
	cfg := validFileConfig(map[string]interface{}{"refresh": "60"})
	_, err := CreateHashicorpVaultFile(cfg, zerolog.Nop())
	if err == nil || err.Error() != "config not valid" {
		t.Errorf("expected config not valid, got: %v", err)
	}
}

func TestCreateHashicorpVaultFile_InvalidTemplate(t *testing.T) {
	cfg := validFileConfig(map[string]interface{}{"template": 123})
	_, err := CreateHashicorpVaultFile(cfg, zerolog.Nop())
	if err == nil || err.Error() != "config not valid" {
		t.Errorf("expected config not valid, got: %v", err)
	}
}

func TestCreateHashicorpVaultFile_InvalidVersion(t *testing.T) {
	cfg := validFileConfig(map[string]interface{}{"version": 1.5})
	_, err := CreateHashicorpVaultFile(cfg, zerolog.Nop())
	if err == nil || err.Error() != "config not valid" {
		t.Errorf("expected config not valid, got: %v", err)
	}
}

func TestHashicorpVaultFile_FileName(t *testing.T) {
	p := HashicorpVaultFile{filePath: "/tmp/secret.txt"}
	if p.FileName() != "/tmp/secret.txt" {
		t.Errorf("unexpected file name: %s", p.FileName())
	}
}

func TestHashicorpVaultFile_writeFileNormalizesPermissions(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(filePath, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	if err := os.Chmod(filePath, 0o600); err != nil {
		t.Fatalf("Chmod error: %v", err)
	}

	p := HashicorpVaultFile{
		filePath: filePath,
		path:     "postgres/prod",
		logger:   zerolog.Nop(),
		mu:       &sync.Mutex{},
	}

	if err := p.writeFile("new-secret"); err != nil {
		t.Fatalf("writeFile error: %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat error: %v", err)
	}
	if got := info.Mode().Perm(); got != sharedprovider.SecretFileMode {
		t.Fatalf("expected mode %04o, got %04o", sharedprovider.SecretFileMode, got)
	}
}
