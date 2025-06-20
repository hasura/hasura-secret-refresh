package azure_key_vault

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

type AzureKeyVault struct {
	client *azsecrets.Client
	cache  *lru.Cache[string, string]
	logger zerolog.Logger
}

const (
	cacheTtl = "cache_ttl"
)

const (
	defaultCacheTtl  = time.Minute * 5
	defaultCacheSize = 100
)

const (
	secretNameHeader = "X-Hasura-Secret-Name"
)

var (
	HeaderNotFound = errors.New("azure_key_vault: required header not found")
	InitError      = errors.New("azure_key_vault: unable to initialize")
)

func Create(config map[string]interface{}, logger zerolog.Logger) (*AzureKeyVault, error) {
	// Parse vault URL
	vaultUrlI, found := config["vault_url"]
	if !found {
		logger.Error().Msg("azure_key_vault: Config 'vault_url' not found")
		return nil, fmt.Errorf("%s: required config 'vault_url' not found", InitError)
	}
	vaultUrl, ok := vaultUrlI.(string)
	if !ok {
		logger.Error().Msg("azure_key_vault: 'vault_url' must be a string")
		return nil, fmt.Errorf("%s: 'vault_url' must be a string", InitError)
	}

	// Parse cache TTL
	cacheTtl_, ok := config[cacheTtl]
	var cacheTtlDuration time.Duration
	if !ok {
		cacheTtlDuration = defaultCacheTtl
	} else {
		cacheTtlI, ok := cacheTtl_.(int)
		if !ok {
			return nil, fmt.Errorf("%s: unable to convert cache_ttl to number", InitError)
		}
		cacheTtlDuration = time.Second * time.Duration(cacheTtlI)
	}

	var cred azcore.TokenCredential

	// Create Azure credential using DefaultAzureCredential
	// This will automatically try different authentication methods in sequence
	defaultCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		logger.Error().Err(err).Msg("azure_key_vault_file: Failed to create default Azure credential")
		return nil, fmt.Errorf("failed to create credential")
	}
	cred = defaultCred

	// Create Key Vault client
	client, err := azsecrets.NewClient(vaultUrl, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create Azure Key Vault client: %w", InitError, err)
	}

	// Create cache
	cache, err := lru.New[string, string](defaultCacheSize)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create cache: %w", InitError, err)
	}

	logger.Info().
		Str("vault_url", vaultUrl).
		Str("cache_ttl", cacheTtlDuration.String()).
		Msg("Creating Azure Key Vault provider")

	return &AzureKeyVault{
		client: client,
		cache:  cache,
		logger: logger,
	}, nil
}

func (provider AzureKeyVault) DeleteConfigHeaders(headers *http.Header) {
	headers.Del(secretNameHeader)
}

func (provider AzureKeyVault) SecretFetcher(headers http.Header) (provider.SecretFetcher, error) {
	secretName := headers.Get(secretNameHeader)
	if secretName == "" {
		return nil, fmt.Errorf("%s: %s", HeaderNotFound, secretNameHeader)
	}
	return secretFetcher{
		AzureKeyVault: &provider,
		secretName:    secretName,
	}, nil
}
