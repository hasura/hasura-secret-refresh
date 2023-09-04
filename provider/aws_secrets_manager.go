package provider

import (
	"log"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
)

type AwsSecretsManager struct {
	cache *secretcache.Cache
}

func (provider AwsSecretsManager) GetSecret(requestConfig RequestConfig) (secret string, err error) {
	secret, err = provider.cache.GetSecretString(string(requestConfig.SecretId))
	return
}

func CreateAwsSecretsManagerProvider(cacheTtl time.Duration) (provider AwsSecretsManager, err error) {
	log.Printf("Creating AWS Secrets Manager provider with cache TTL %s", cacheTtl.String())
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
