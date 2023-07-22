package store

import (
	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
)

type awsSecretsManager struct {
	cache *secretcache.Cache
}

func (store awsSecretsManager) FetchSecrets(keys []string) (secrets map[string]string, err error) {
	secrets = make(map[string]string)
	for _, secretId := range keys {
		var secret string
		secret, err = store.cache.GetSecretString(secretId)
		if err != nil {
			//TODO: handle error
		}
		secrets[secretId] = secret
	}
	return
}

func createAwsSecretsManagerStore(config config) (store awsSecretsManager, err error) {
	secretsCache, err := secretcache.New(
		func(c *secretcache.Cache) { c.CacheConfig.CacheItemTTL = config.CacheTtl.Nanoseconds() },
	)
	if err != nil {
		// TODO: handle error
	}
	return awsSecretsManager{cache: secretsCache}, nil
}
