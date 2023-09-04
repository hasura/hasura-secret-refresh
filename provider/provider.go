package provider

type Provider interface {
	GetSecret(requestConfig RequestConfig) (secret string, err error)
}
