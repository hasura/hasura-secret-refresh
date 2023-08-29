package aws_secrets_manager

import (
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	secretsTemplate "github.com/hasura/hasura-secret-refresh/template"
)

type AwsSecretsManager struct {
	cache *secretcache.Cache
}

func (store AwsSecretsManager) FetchSecrets(keys []secretsTemplate.SecretKey) (secrets map[secretsTemplate.SecretKey]secretsTemplate.Secret, err error) {
	secrets = make(map[secretsTemplate.SecretKey]secretsTemplate.Secret)
	for _, secretId := range keys {
		var secret string
		secret, err = store.cache.GetSecretString(string(secretId))
		if err != nil {
			return secrets, err
		}
		secrets[secretId] = secretsTemplate.Secret(secret)
	}
	return
}

func CreateAwsSecretsManagerStore(cacheTtl time.Duration) (store AwsSecretsManager, err error) {
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
