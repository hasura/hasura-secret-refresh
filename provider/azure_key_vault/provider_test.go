package azure_key_vault

import (
	"net/http"
	"testing"

	"github.com/rs/zerolog"
)

func TestCreate_MissingVaultUrl(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"cache_ttl": 300,
	}

	_, err := Create(config, logger)
	if err == nil {
		t.Error("Expected error when vault_url is missing")
	}
	if err.Error() != "azure_key_vault: unable to initialize: required config 'vault_url' not found" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreate_InvalidVaultUrl(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url": 123, // Invalid type
		"cache_ttl": 300,
	}

	_, err := Create(config, logger)
	if err == nil {
		t.Error("Expected error when vault_url is invalid type")
	}
	if err.Error() != "azure_key_vault: unable to initialize: 'vault_url' must be a string" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreate_InvalidCacheTtl(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url": "https://test.vault.azure.net/",
		"cache_ttl": "invalid", // Invalid type
	}

	_, err := Create(config, logger)
	if err == nil {
		t.Error("Expected error when cache_ttl is invalid type")
	}
	if err.Error() != "azure_key_vault: unable to initialize: unable to convert cache_ttl to number" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreate_MissingClientSecret(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url": "https://test.vault.azure.net/",
		"cache_ttl": 300,
		"client_id": "test-client-id",
		// Missing client_secret
	}

	_, err := Create(config, logger)
	if err == nil {
		t.Error("Expected error when client_secret is missing but client_id is provided")
	}
	if err.Error() != "azure_key_vault: unable to initialize: client_secret is required when using client_id" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCreate_MissingTenantId(t *testing.T) {
	logger := zerolog.Nop()
	config := map[string]interface{}{
		"vault_url":     "https://test.vault.azure.net/",
		"cache_ttl":     300,
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
		// Missing tenant_id
	}

	_, err := Create(config, logger)
	if err == nil {
		t.Error("Expected error when tenant_id is missing but client_id and client_secret are provided")
	}
	if err.Error() != "azure_key_vault: unable to initialize: tenant_id is required when using client_id and client_secret" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestDeleteConfigHeaders(t *testing.T) {
	// Test the header deletion logic with a mock
	provider := &AzureKeyVault{}

	headers := http.Header{}
	headers.Set("X-Hasura-Secret-Name", "test-secret")
	headers.Set("Other-Header", "test-value")

	provider.DeleteConfigHeaders(&headers)

	if headers.Get("X-Hasura-Secret-Name") != "" {
		t.Error("Expected X-Hasura-Secret-Name header to be deleted")
	}
	if headers.Get("Other-Header") != "test-value" {
		t.Error("Expected Other-Header to remain unchanged")
	}
}

func TestSecretFetcher_MissingSecretName(t *testing.T) {
	provider := &AzureKeyVault{}

	headers := http.Header{}
	// Missing X-Hasura-Secret-Name header

	_, err := provider.SecretFetcher(headers)
	if err == nil {
		t.Error("Expected error when X-Hasura-Secret-Name header is missing")
	}
	if err.Error() != "azure_key_vault: required header not found: X-Hasura-Secret-Name" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestSecretFetcher_ValidSecretName(t *testing.T) {
	provider := &AzureKeyVault{}

	headers := http.Header{}
	headers.Set("X-Hasura-Secret-Name", "test-secret")

	fetcher, err := provider.SecretFetcher(headers)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	secretFetcher, ok := fetcher.(secretFetcher)
	if !ok {
		t.Error("Expected secretFetcher type")
	}

	if secretFetcher.secretName != "test-secret" {
		t.Errorf("Expected secret name 'test-secret', got '%s'", secretFetcher.secretName)
	}
}
