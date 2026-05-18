package hashicorp_vault

import (
	"errors"
	"fmt"
)

type secretFetcher struct {
	*HashicorpVault
	mount   string
	path    string
	field   string
	version string
}

var (
	ErrUnableToFetch = errors.New("hashicorp_vault: unable to fetch secret")
)

// cacheKey is "<mount>/<path>@<version>[#field]" so cache entries are
// unique across mounts, versions, and field projections.
func (f secretFetcher) cacheKey() string {
	return fmt.Sprintf("%s/%s@%s#%s", f.mount, f.path, f.version, f.field)
}

func (f secretFetcher) FetchSecret() (string, error) {
	key := f.cacheKey()
	if cached, found := f.cache.Get(key); found {
		f.logger.Debug().Str("vault_path", f.path).Msg("hashicorp_vault: secret found in cache")
		return cached, nil
	}

	f.logger.Info().Str("vault_path", f.path).Msg("hashicorp_vault: fetching secret from Vault")

	data, err := readKVv2WithTimeout(f.client.client(), f.mount, f.path, f.version, f.logger)
	if err != nil {
		f.logger.Err(err).Str("vault_path", f.path).Msg("hashicorp_vault: failed to fetch secret")
		return "", fmt.Errorf("%w: %v", ErrUnableToFetch, err)
	}

	value, err := extractField(data, f.field)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnableToFetch, err)
	}

	f.cache.Add(key, value)
	f.logger.Debug().Str("vault_path", f.path).Msg("hashicorp_vault: secret cached")
	return value, nil
}
