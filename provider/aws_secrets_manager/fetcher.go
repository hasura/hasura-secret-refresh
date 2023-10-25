package aws_secrets_manager

import (
	"errors"
	"fmt"
)

type secretFetcher struct {
	*AwsSecretsManager
	secretId string
}

var (
	UnableToFetch = errors.New("aws_secrets_manager: unable to fetch secret")
)

func (fetcher secretFetcher) FetchSecret() (string, error) {
	secret, err := fetcher.cache.GetSecretString(fetcher.secretId)
	return secret, fmt.Errorf("%s: %w", UnableToFetch, err)
}
