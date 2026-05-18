package hashicorp_vault

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func validAuthMap() map[string]interface{} {
	return map[string]interface{}{
		"method": "kubernetes",
		"role":   "hasura-sidecar",
	}
}

func TestParseVaultConfig_MissingVaultAddr(t *testing.T) {
	_, err := parseVaultConfig(map[string]interface{}{
		"auth": validAuthMap(),
	})
	if err == nil || !strings.Contains(err.Error(), "vault_addr") {
		t.Fatalf("expected vault_addr error, got: %v", err)
	}
}

func TestParseVaultConfig_VaultAddrWrongType(t *testing.T) {
	_, err := parseVaultConfig(map[string]interface{}{
		"vault_addr": 123,
		"auth":       validAuthMap(),
	})
	if err == nil || !strings.Contains(err.Error(), "'vault_addr' must be a string") {
		t.Fatalf("expected vault_addr type error, got: %v", err)
	}
}

func TestParseVaultConfig_MissingAuth(t *testing.T) {
	_, err := parseVaultConfig(map[string]interface{}{
		"vault_addr": "https://vault.example.com:8200",
	})
	if err == nil || !strings.Contains(err.Error(), "'auth' not found") {
		t.Fatalf("expected auth error, got: %v", err)
	}
}

func TestParseVaultConfig_MissingRole(t *testing.T) {
	_, err := parseVaultConfig(map[string]interface{}{
		"vault_addr": "https://vault.example.com:8200",
		"auth":       map[string]interface{}{"method": "kubernetes"},
	})
	if err == nil || !strings.Contains(err.Error(), "auth.role") {
		t.Fatalf("expected auth.role error, got: %v", err)
	}
}

func TestParseVaultConfig_UnsupportedMethod(t *testing.T) {
	_, err := parseVaultConfig(map[string]interface{}{
		"vault_addr": "https://vault.example.com:8200",
		"auth": map[string]interface{}{
			"method": "approle",
			"role":   "hasura",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "only auth method") {
		t.Fatalf("expected unsupported method error, got: %v", err)
	}
}

func TestParseVaultConfig_Defaults(t *testing.T) {
	vc, err := parseVaultConfig(map[string]interface{}{
		"vault_addr": "https://vault.example.com:8200",
		"auth":       validAuthMap(),
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if vc.MountPath != defaultMountPath {
		t.Errorf("expected mount_path default %q, got %q", defaultMountPath, vc.MountPath)
	}
	if vc.JwtPath != defaultJwtPath {
		t.Errorf("expected jwt_path default %q, got %q", defaultJwtPath, vc.JwtPath)
	}
	if vc.AuthMethod != authMethodK8s {
		t.Errorf("expected default auth method, got: %s", vc.AuthMethod)
	}
}

func TestParseVaultConfig_AllFields(t *testing.T) {
	vc, err := parseVaultConfig(map[string]interface{}{
		"vault_addr": "https://vault.example.com:8200",
		"namespace":  "engineering/team-a",
		"tls": map[string]interface{}{
			"ca_cert":     "/etc/vault/ca.pem",
			"skip_verify": true,
		},
		"auth": map[string]interface{}{
			"method":     "kubernetes",
			"role":       "hasura-sidecar",
			"mount_path": "k8s-prod",
			"jwt_path":   "/var/run/sa/token",
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if vc.Namespace != "engineering/team-a" {
		t.Errorf("namespace mismatch: %s", vc.Namespace)
	}
	if vc.CACert != "/etc/vault/ca.pem" {
		t.Errorf("ca_cert mismatch: %s", vc.CACert)
	}
	if !vc.SkipVerify {
		t.Error("expected skip_verify true")
	}
	if vc.MountPath != "k8s-prod" {
		t.Errorf("mount_path mismatch: %s", vc.MountPath)
	}
	if vc.JwtPath != "/var/run/sa/token" {
		t.Errorf("jwt_path mismatch: %s", vc.JwtPath)
	}
	if vc.AuthRole != "hasura-sidecar" {
		t.Errorf("role mismatch: %s", vc.AuthRole)
	}
}

func TestBuildKVv2Path(t *testing.T) {
	cases := []struct{ mount, path, want string }{
		{"secret", "postgres/prod", "secret/data/postgres/prod"},
		{"secret/", "/postgres/prod", "secret/data/postgres/prod"},
		{"", "postgres/prod", "secret/data/postgres/prod"},
		{"secret", "data/postgres/prod", "secret/data/postgres/prod"},
		{"kv", "app/foo", "kv/data/app/foo"},
	}
	for _, c := range cases {
		got := buildKVv2Path(c.mount, c.path)
		if got != c.want {
			t.Errorf("buildKVv2Path(%q,%q)=%q want %q", c.mount, c.path, got, c.want)
		}
	}
}

func TestExtractField_Whole(t *testing.T) {
	data := map[string]interface{}{"username": "u", "password": "p"}
	out, err := extractField(data, "")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.Contains(out, "username") || !strings.Contains(out, "password") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestExtractField_StringValue(t *testing.T) {
	out, err := extractField(map[string]interface{}{"username": "alice"}, "username")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if out != "alice" {
		t.Errorf("expected 'alice', got %q", out)
	}
}

func TestExtractField_Missing(t *testing.T) {
	_, err := extractField(map[string]interface{}{}, "username")
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestDeleteConfigHeaders(t *testing.T) {
	p := &HashicorpVault{}
	headers := http.Header{}
	headers.Set("X-Hasura-Vault-Path", "data/postgres/prod")
	headers.Set("X-Hasura-Vault-Field", "password")
	headers.Set("Other", "v")

	p.DeleteConfigHeaders(&headers)

	if headers.Get("X-Hasura-Vault-Path") != "" {
		t.Error("expected vault path header removed")
	}
	if headers.Get("X-Hasura-Vault-Field") != "" {
		t.Error("expected vault field header removed")
	}
	if headers.Get("Other") != "v" {
		t.Error("expected unrelated header preserved")
	}
}

func TestSecretFetcher_MissingPathHeader(t *testing.T) {
	p := &HashicorpVault{defaultMount: "secret"}
	if _, err := p.SecretFetcher(http.Header{}); err == nil {
		t.Error("expected error when path header missing")
	}
}

func TestSecretFetcher_PopulatesFields(t *testing.T) {
	p := HashicorpVault{defaultMount: "secret", logger: zerolog.Nop()}
	h := http.Header{}
	h.Set("X-Hasura-Vault-Path", "postgres/prod")
	h.Set("X-Hasura-Vault-Field", "password")
	h.Set("X-Hasura-Vault-Version", "3")

	f, err := p.SecretFetcher(h)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	sf, ok := f.(secretFetcher)
	if !ok {
		t.Fatalf("unexpected fetcher type")
	}
	if sf.path != "postgres/prod" || sf.field != "password" || sf.version != "3" || sf.mount != "secret" {
		t.Errorf("fetcher fields wrong: %+v", sf)
	}
}

func TestCreate_MissingVaultAddr(t *testing.T) {
	_, err := Create(map[string]interface{}{}, zerolog.Nop())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unable to initialize") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreate_InvalidCacheTtl(t *testing.T) {
	_, err := Create(map[string]interface{}{
		"vault_addr": "https://vault.example.com:8200",
		"auth":       validAuthMap(),
		"cache_ttl":  "five",
	}, zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "cache_ttl") {
		t.Errorf("expected cache_ttl error, got: %v", err)
	}
}
