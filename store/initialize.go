package store

import (
	"strconv"
	"time"

	"github.com/hasura/hasura-secret-refresh/process_secrets"
)

type config struct {
	CacheTtl time.Duration
}

func InitializeSecretStore(configMap map[string]string) (store process_secrets.SecretsStore, err error) {
	durationSeconds, err := strconv.Atoi(configMap["cache_ttl"])
	if err != nil {
		//TODO: Handle error
	}
	return createAwsSecretsManagerStore(
		config{
			CacheTtl: time.Duration(int64(durationSeconds) * int64(time.Second)),
		},
	)
}
