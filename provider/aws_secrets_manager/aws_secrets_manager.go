package aws_secrets_manager

import (
	"net/http"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

type AwsSecretsManager struct {
	cache *secretcache.Cache
}

func (provider AwsSecretsManager) ParseRequestConfig(header http.Header) (provider.GetSecret, error) {
	config, err := GetRequestConfig(header)
	if err != nil {
		return nil, err
	}
	return func() (secret string, err error) {
		secret, err = provider.cache.GetSecretString(string(config.SecretId))
		return
	}, nil
}

func (provider AwsSecretsManager) DeleteConfigHeaders(header *http.Header) {
	DeleteConfigHeaders(header)
}

func CreateAwsSecretsManagerProvider(cacheTtl time.Duration, logger zerolog.Logger) (provider AwsSecretsManager, err error) {
	logger.Info().
		Str("cache_ttl", cacheTtl.String()).
		Msg("Creating provider")
	secretsCache, err := secretcache.New(
		func(c *secretcache.Cache) { c.CacheConfig.CacheItemTTL = GetCacheTtlFromDuration(cacheTtl) },
	)
	if err != nil {
		return
	}
	return AwsSecretsManager{cache: secretsCache}, nil
}

func GetCacheTtlFromDuration(cacheTtl time.Duration) int64 {
	return cacheTtl.Nanoseconds()
}
