package provider

type Provider interface {
	GetSecret(secretId string) (secret string, err error)
}
