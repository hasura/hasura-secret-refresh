package aws_secrets_manager

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

type AwsSecretsManager struct {
	cache *secretcache.Cache
}

const (
	cacheTtl = "cache_ttl"
)

const (
	defaultCacheTtl = time.Minute * 5
)

const (
	secretIdHeader = "X-Hasura-Secret-Id"
)

var (
	HeaderNotFound = errors.New("aws_secrets_manager: required header not found")
	InitError      = errors.New("aws_secrets_manager: unable to initialize")
)

func Create(config map[string]interface{}, logger zerolog.Logger) (*AwsSecretsManager, error) {
	cacheTtl_, ok := config[cacheTtl]
	var cacheTtl time.Duration
	if !ok {
		cacheTtl = defaultCacheTtl
	} else {
		cacheTtlI, ok := cacheTtl_.(int)
		if !ok {
			return nil, fmt.Errorf(
				"%s: unable to convert cacheTtl to number", InitError,
			)
		}
		cacheTtl = time.Second * time.Duration(cacheTtlI)
	}
	logger.Info().
		Str("cache_ttl", cacheTtl.String()).
		Msg("Creating provider")
	secretsCache, err := secretcache.New(
		func(c *secretcache.Cache) {
			c.CacheConfig.CacheItemTTL = cacheTtl.Nanoseconds()
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s: unable to convert cacheTtl to int: %w", InitError, err,
		)
	}
	return &AwsSecretsManager{cache: secretsCache}, nil
}

func (provider AwsSecretsManager) DeleteConfigHeaders(headers *http.Header) {
	headers.Del(secretIdHeader)
}

func (provider AwsSecretsManager) SecretFetcher(headers http.Header) (provider.SecretFetcher, error) {
	secretId := headers.Get(secretIdHeader)
	if secretId != "" {
		return secretFetcher{}, fmt.Errorf("%s: %s", HeaderNotFound, secretIdHeader)
	}
	return secretFetcher{
		AwsSecretsManager: &provider,
		secretId:          secretId,
	}, nil
}
