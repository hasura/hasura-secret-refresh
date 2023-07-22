package process_secrets

type SecretsStore interface {
	FetchSecrets(keys []string) (secrets map[string]string, err error)
}
