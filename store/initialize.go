package store

import (
	"time"

	"github.com/hasura/hasura-secret-refresh/process_secrets"
)

type config struct {
	CacheTtl time.Duration
}

func InitializeSecretStore(configMap map[string]interface{}) (store process_secrets.SecretsStore, err error) {
	durationSeconds := configMap["cache_ttl"].(int)
	return createAwsSecretsManagerStore(
		config{
			CacheTtl: time.Duration(int64(durationSeconds) * int64(time.Second)),
		},
	)
}
