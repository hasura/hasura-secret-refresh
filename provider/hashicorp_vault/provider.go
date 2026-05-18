package hashicorp_vault

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

type HashicorpVault struct {
	client      *vaultClient
	cache       *lru.Cache[string, string]
	defaultMount string
	logger      zerolog.Logger
}

const (
	cacheTtlKey = "cache_ttl"
	mountKey    = "mount"
)

const (
	defaultCacheTtl  = time.Minute * 5
	defaultCacheSize = 100
	defaultMount     = "secret"
)

const (
	vaultPathHeader    = "X-Hasura-Vault-Path"
	vaultFieldHeader   = "X-Hasura-Vault-Field"
	vaultVersionHeader = "X-Hasura-Vault-Version"
	vaultMountHeader   = "X-Hasura-Vault-Mount"
)

var (
	ErrHeaderNotFound = errors.New("hashicorp_vault: required header not found")
	ErrInit           = errors.New("hashicorp_vault: unable to initialize")
)

// Create builds the HTTP provider variant of the HashiCorp Vault provider.
// It authenticates eagerly so that misconfiguration surfaces at startup.
func Create(config map[string]interface{}, logger zerolog.Logger) (*HashicorpVault, error) {
	vc, err := parseVaultConfig(config)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInit, err)
	}

	cacheTtlDuration := defaultCacheTtl
	if cacheTtlI, ok := config[cacheTtlKey]; ok {
		cacheTtl, ok := cacheTtlI.(int)
		if !ok {
			return nil, fmt.Errorf("%w: unable to convert cache_ttl to number", ErrInit)
		}
		cacheTtlDuration = time.Second * time.Duration(cacheTtl)
	}

	mount := defaultMount
	if mountI, ok := config[mountKey]; ok {
		m, ok := mountI.(string)
		if !ok {
			return nil, fmt.Errorf("%w: 'mount' must be a string", ErrInit)
		}
		if m != "" {
			mount = m
		}
	}

	client, err := newAuthenticatedClient(vc, logger)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInit, err)
	}

	cache, err := lru.New[string, string](defaultCacheSize)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create cache: %v", ErrInit, err)
	}

	logger.Info().
		Str("vault_addr", vc.Address).
		Str("namespace", vc.Namespace).
		Str("mount", mount).
		Str("cache_ttl", cacheTtlDuration.String()).
		Msg("Creating HashiCorp Vault provider")

	return &HashicorpVault{
		client:       client,
		cache:        cache,
		defaultMount: mount,
		logger:       logger,
	}, nil
}

func (p HashicorpVault) DeleteConfigHeaders(headers *http.Header) {
	headers.Del(vaultPathHeader)
	headers.Del(vaultFieldHeader)
	headers.Del(vaultVersionHeader)
	headers.Del(vaultMountHeader)
}

func (p HashicorpVault) SecretFetcher(headers http.Header) (provider.SecretFetcher, error) {
	path := strings.TrimSpace(headers.Get(vaultPathHeader))
	if path == "" {
		return nil, fmt.Errorf("%w: %s", ErrHeaderNotFound, vaultPathHeader)
	}
	field := headers.Get(vaultFieldHeader)
	version := headers.Get(vaultVersionHeader)
	mount := headers.Get(vaultMountHeader)
	if mount == "" {
		mount = p.defaultMount
	}
	return secretFetcher{
		HashicorpVault: &p,
		mount:          mount,
		path:           path,
		field:          field,
		version:        version,
	}, nil
}
