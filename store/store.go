package store

import secretsTemplate "github.com/hasura/hasura-secret-refresh/template"

type SecretsStore interface {
	FetchSecrets(keys []secretsTemplate.SecretKey) (secrets map[secretsTemplate.SecretKey]secretsTemplate.Secret, err error)
}
