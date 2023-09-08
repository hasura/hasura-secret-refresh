package provider

import (
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"github.com/rs/zerolog"
)

type AwsSecretsManager struct {
	cache *secretcache.Cache
}

func (provider AwsSecretsManager) GetSecret(secretId string) (secret string, err error) {
	secret, err = provider.cache.GetSecretString(string(secretId))
	return
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
