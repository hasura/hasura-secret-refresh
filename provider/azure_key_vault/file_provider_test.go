package azure_key_vault

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestCreateAzureKeyVaultFile_MissingVaultUrl(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"path":        "/tmp/test-secret",
		"secret_name": "test-secret",
		"refresh":     60,
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when vault_url is missing")
	}
	if err.Error() != "required configs not found" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_InvalidVaultUrl(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":   123, // Invalid type
		"path":        "/tmp/test-secret",
		"secret_name": "test-secret",
		"refresh":     60,
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when vault_url is invalid type")
	}
	if err.Error() != "config not valid" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_MissingPath(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":   "https://test.vault.azure.net/",
		"secret_name": "test-secret",
		"refresh":     60,
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when path is missing")
	}
	if err.Error() != "required configs not found" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_InvalidPath(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":   "https://test.vault.azure.net/",
		"path":        123, // Invalid type
		"secret_name": "test-secret",
		"refresh":     60,
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when path is invalid type")
	}
	if err.Error() != "config not valid" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_MissingSecretName(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url": "https://test.vault.azure.net/",
		"path":      "/tmp/test-secret",
		"refresh":   60,
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when secret_name is missing")
	}
	if err.Error() != "required configs not found" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_InvalidSecretName(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":   "https://test.vault.azure.net/",
		"path":        "/tmp/test-secret",
		"secret_name": 123, // Invalid type
		"refresh":     60,
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when secret_name is invalid type")
	}
	if err.Error() != "config not valid" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_MissingRefresh(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":   "https://test.vault.azure.net/",
		"path":        "/tmp/test-secret",
		"secret_name": "test-secret",
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when refresh is missing")
	}
	if err.Error() != "required configs not found" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_InvalidRefresh(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":   "https://test.vault.azure.net/",
		"path":        "/tmp/test-secret",
		"secret_name": "test-secret",
		"refresh":     "invalid", // Invalid type
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when refresh is invalid type")
	}
	if err.Error() != "config not valid" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_InvalidSecretVersion(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":      "https://test.vault.azure.net/",
		"path":           "/tmp/test-secret",
		"secret_name":    "test-secret",
		"refresh":        60,
		"secret_version": 123, // Invalid type
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when secret_version is invalid type")
	}
	if err.Error() != "config not valid" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_InvalidTemplate(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":   "https://test.vault.azure.net/",
		"path":        "/tmp/test-secret",
		"secret_name": "test-secret",
		"refresh":     60,
		"template":    123, // Invalid type
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when template is invalid type")
	}
	if err.Error() != "config not valid" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_MissingClientSecret(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":   "https://test.vault.azure.net/",
		"path":        "/tmp/test-secret",
		"secret_name": "test-secret",
		"refresh":     60,
		"client_id":   "test-client-id",
		// Missing client_secret
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when client_secret is missing but client_id is provided")
	}
	if err.Error() != "config not valid" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreateAzureKeyVaultFile_MissingTenantId(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":     "https://test.vault.azure.net/",
		"path":          "/tmp/test-secret",
		"secret_name":   "test-secret",
		"refresh":       60,
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
		// Missing tenant_id
	}

	_, err := CreateAzureKeyVaultFile(config, logger)
	if err == nil {
		t.Error("Expected error when tenant_id is missing but client_id and client_secret are provided")
	}
	if err.Error() != "config not valid" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestAzureKeyVaultFile_FileName(t *testing.T) {
	provider := AzureKeyVaultFile{
		filePath: "/tmp/test-secret",
	}

	fileName := provider.FileName()
	if fileName != "/tmp/test-secret" {
		t.Errorf("Expected file name '/tmp/test-secret', got '%s'", fileName)
	}
}
