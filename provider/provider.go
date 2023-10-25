package provider

import "net/http"

type HttpProvider interface {
	SecretFetcher(http.Header) (SecretFetcher, error)
	DeleteConfigHeaders(*http.Header)
}

type SecretFetcher interface {
	FetchSecret() (string, error)
}
