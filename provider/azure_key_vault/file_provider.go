package azure_key_vault

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/hasura/hasura-secret-refresh/template"
	"github.com/rs/zerolog"
)

type AzureKeyVaultFile struct {
	refreshInterval time.Duration
	client          *azsecrets.Client
	filePath        string
	secretName      string
	secretVersion   string
	template        string
	logger          zerolog.Logger
	mu              *sync.Mutex
}

func CreateAzureKeyVaultFile(config map[string]interface{}, logger zerolog.Logger) (AzureKeyVaultFile, error) {
	// Parse vault URL
	vaultUrlI, found := config["vault_url"]
	if !found {
		logger.Error().Msg("azure_key_vault_file: Config 'vault_url' not found")
		return AzureKeyVaultFile{}, fmt.Errorf("azure_key_vault_file: required config 'vault_url' not found")
	}
	vaultUrl, ok := vaultUrlI.(string)
	if !ok {
		logger.Error().Msg("azure_key_vault_file: 'vault_url' must be a string")
		return AzureKeyVaultFile{}, fmt.Errorf("config not valid")
	}

	// Parse file path
	filePathI, found := config["path"]
	if !found {
		logger.Error().Msg("azure_key_vault_file: Config 'path' not found")
		return AzureKeyVaultFile{}, fmt.Errorf("required configs not found")
	}
	filePath, ok := filePathI.(string)
	if !ok {
		logger.Error().Msg("azure_key_vault_file: 'path' must be a string")
		return AzureKeyVaultFile{}, fmt.Errorf("config not valid")
	}

	// Parse secret name
	secretNameI, found := config["secret_name"]
	if !found {
		logger.Error().Msg("azure_key_vault_file: Config 'secret_name' not found")
		return AzureKeyVaultFile{}, fmt.Errorf("required configs not found")
	}
	secretName, ok := secretNameI.(string)
	if !ok {
		logger.Error().Msg("azure_key_vault_file: 'secret_name' must be a string")
		return AzureKeyVaultFile{}, fmt.Errorf("config not valid")
	}

	// Parse refresh interval
	refreshIntervalI, found := config["refresh"]
	if !found {
		logger.Error().Msg("azure_key_vault_file: Config 'refresh' not found")
		return AzureKeyVaultFile{}, fmt.Errorf("required configs not found")
	}
	refreshIntervalInt, ok := refreshIntervalI.(int)
	if !ok {
		logger.Error().Msg("azure_key_vault_file: 'refresh' must be an integer")
		return AzureKeyVaultFile{}, fmt.Errorf("config not valid")
	}
	refreshInterval := time.Duration(refreshIntervalInt) * time.Second

	// Parse optional secret version
	secretVersion := ""
	if secretVersionI, ok := config["secret_version"]; ok {
		secretVersion, ok = secretVersionI.(string)
		if !ok {
			logger.Error().Msg("azure_key_vault_file: 'secret_version' must be a string")
			return AzureKeyVaultFile{}, fmt.Errorf("config not valid")
		}
	}

	// Parse optional template
	secretTemplate := ""
	if secretTemplateI, ok := config["template"]; ok {
		secretTemplate, ok = secretTemplateI.(string)
		if !ok {
			logger.Error().Msg("azure_key_vault_file: 'template' must be a string")
			return AzureKeyVaultFile{}, fmt.Errorf("config not valid")
		}
	}

	// Create Azure credential
	var cred azcore.TokenCredential

	// Create Azure credential using DefaultAzureCredential
	// This will automatically try different authentication methods in sequence
	defaultCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		logger.Error().Err(err).Msg("azure_key_vault_file: Failed to create default Azure credential")
		return AzureKeyVaultFile{}, fmt.Errorf("failed to create credential")
	}
	cred = defaultCred

	// Create Key Vault client
	client, err := azsecrets.NewClient(vaultUrl, cred, nil)
	if err != nil {
		logger.Error().Err(err).Msg("azure_key_vault_file: Failed to create Azure Key Vault client")
		return AzureKeyVaultFile{}, fmt.Errorf("failed to create client")
	}

	azureKv := AzureKeyVaultFile{
		refreshInterval: refreshInterval,
		filePath:        filePath,
		client:          client,
		secretName:      secretName,
		secretVersion:   secretVersion,
		logger:          logger,
		template:        secretTemplate,
		mu:              &sync.Mutex{},
	}

	logger.Info().
		Str("refresh", refreshInterval.String()).
		Str("file_path", filePath).
		Str("secret_name", secretName).
		Str("vault_url", vaultUrl).
		Msg("Creating Azure Key Vault file provider")

	return azureKv, nil
}

func (provider AzureKeyVaultFile) Start() {
	err := os.WriteFile(provider.filePath, []byte(""), 0600)
	if err != nil {
		provider.logger.Err(err).Msgf("azure_key_vault_file: Error occurred while writing to file %s", provider.filePath)
	}
	for {
		secret, err := provider.getSecret()
		if err != nil {
			time.Sleep(provider.refreshInterval)
			continue
		}
		err = provider.writeFile(secret)
		if err != nil {
			time.Sleep(provider.refreshInterval)
			continue
		}
		provider.logger.Info().Msgf("azure_key_vault_file: Successfully fetched secret %s. Fetching again in %s", provider.secretName, provider.refreshInterval)
		time.Sleep(provider.refreshInterval)
	}
}

func (provider AzureKeyVaultFile) Refresh() error {
	provider.logger.Info().Msgf("azure_key_vault_file: Refresh invoked for secret %s", provider.secretName)
	secret, err := provider.getSecret()
	if err != nil {
		return err
	}
	err = provider.writeFile(secret)
	if err != nil {
		return err
	}
	provider.logger.Info().Msgf("azure_key_vault_file: Successfully refreshed secret %s upon invocation", provider.secretName)
	return nil
}

func (provider AzureKeyVaultFile) FileName() string {
	return provider.filePath
}

func (provider AzureKeyVaultFile) getSecret() (string, error) {
	provider.logger.Info().Msgf("azure_key_vault_file: Fetching secret %s", provider.secretName)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := provider.client.GetSecret(ctx, provider.secretName, provider.secretVersion, nil)
	if err != nil {
		provider.logger.Err(err).Msgf("azure_key_vault_file: Error occurred while retrieving secret '%s' from Azure Key Vault", provider.secretName)
		return "", err
	}

	if resp.Value == nil {
		provider.logger.Error().Msgf("azure_key_vault_file: Secret value is nil for secret '%s'", provider.secretName)
		return "", fmt.Errorf("secret value is nil")
	}

	secretString := *resp.Value
	if provider.template != "" {
		templ := template.Template{Templ: provider.template, Logger: provider.logger}
		secretString = templ.Substitute(secretString)
	}
	return secretString, nil
}

func (provider AzureKeyVaultFile) writeFile(secretString string) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	err := os.WriteFile(provider.filePath, []byte(secretString), 0600)
	if err != nil {
		provider.logger.Err(err).Msgf("azure_key_vault_file: Error occurred while writing secret %s to file %s", provider.secretName, provider.filePath)
		return err
	}
	provider.logger.Info().Msgf("azure_key_vault_file: Successfully wrote secret %s to file %s", provider.secretName, provider.filePath)
	return nil
}
