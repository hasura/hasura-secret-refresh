package provider

import "net/http"

type HttpProvider interface {
	SecretFetcher(http.Header) (SecretFetcher, error)
	DeleteConfigHeaders(*http.Header)
}

type FileProvider interface {
	Start()
	Refresh() error
	FileName() string
}

type SecretFetcher interface {
	FetchSecret() (string, error)
}
