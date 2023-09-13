package provider

import "net/http"

type GetSecret func() (secret string, err error)

type Provider interface {
	ParseRequestConfig(header http.Header) (GetSecret, error)
	DeleteConfigHeaders(header *http.Header)
}
