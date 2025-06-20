package azure_key_vault

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type secretFetcher struct {
	*AzureKeyVault
	secretName string
}

var (
	UnableToFetch = errors.New("azure_key_vault: unable to fetch secret")
)

func (fetcher secretFetcher) FetchSecret() (string, error) {
	// Check cache first
	if cachedSecret, found := fetcher.cache.Get(fetcher.secretName); found {
		fetcher.logger.Debug().Str("secret_name", fetcher.secretName).Msg("azure_key_vault: Secret found in cache")
		return cachedSecret, nil
	}

	// Fetch from Azure Key Vault
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fetcher.logger.Info().Str("secret_name", fetcher.secretName).Msg("azure_key_vault: Fetching secret from Azure Key Vault")
	
	resp, err := fetcher.client.GetSecret(ctx, fetcher.secretName, "", nil)
	if err != nil {
		fetcher.logger.Err(err).Str("secret_name", fetcher.secretName).Msg("azure_key_vault: Failed to fetch secret")
		return "", fmt.Errorf("%s: %w", UnableToFetch, err)
	}

	if resp.Value == nil {
		fetcher.logger.Error().Str("secret_name", fetcher.secretName).Msg("azure_key_vault: Secret value is nil")
		return "", fmt.Errorf("%s: secret value is nil", UnableToFetch)
	}

	secretValue := *resp.Value
	
	// Cache the secret
	fetcher.cache.Add(fetcher.secretName, secretValue)
	fetcher.logger.Debug().Str("secret_name", fetcher.secretName).Msg("azure_key_vault: Secret cached successfully")

	return secretValue, nil
}
