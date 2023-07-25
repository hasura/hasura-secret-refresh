package store

import (
	"log"
	"time"

	"github.com/hasura/hasura-secret-refresh/process_secrets"
)

type config struct {
	CacheTtl time.Duration
}

func InitializeSecretStore(configMap map[string]interface{}) (store process_secrets.SecretsStore, err error) {
	cacheTtl, ok := configMap["cache_ttl"]
	if !ok {
		log.Fatal("Unable to find config 'cache_ttl'. Please add this to the configuration with value representing the number of seconds.")
	}
	durationF, ok := cacheTtl.(float64)
	durationI := int64(durationF)
	duration := time.Duration(durationI * int64(time.Second))
	log.Printf("Initializing cache with TTL %v", duration)
	if !ok {
		log.Fatalf("Invalid value '%v' for config 'cache_ttl'. The value should be a number representing the number of seconds.", cacheTtl)
	}
	return createAwsSecretsManagerStore(
		config{
			CacheTtl: duration,
		},
	)
}
