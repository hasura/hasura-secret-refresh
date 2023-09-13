package server

import (
	"net/http"

	requestconfig "github.com/hasura/hasura-secret-refresh/request_config"
)

type RequestConfig struct {
	DestinationUrl string
	SecretProvider string
	HeaderTemplate string
}

const (
	ForwardToHeader      = "X-Hasura-Forward-To"
	SecretProviderHeader = "X-Hasura-Secret-Provider"
	TemplateHeader       = "X-Hasura-Secret-Header"
)

func GetRequestConfig(headers http.Header) (
	requestConfig RequestConfig, err error,
) {
	parseRequestConfigInput := []requestconfig.ParseRequestConfigInput{
		{
			HeaderName:   ForwardToHeader,
			UpdateConfig: func(headerVal string) { requestConfig.DestinationUrl = headerVal },
		},
		{
			HeaderName:   SecretProviderHeader,
			UpdateConfig: func(headerVal string) { requestConfig.SecretProvider = headerVal },
		},
		{
			HeaderName:   TemplateHeader,
			UpdateConfig: func(headerVal string) { requestConfig.HeaderTemplate = headerVal },
		},
	}
	err = requestconfig.ParseRequestConfig(headers, parseRequestConfigInput)
	if err != nil {
		return
	}
	return requestConfig, nil
}

func DeleteConfigHeaders(header *http.Header) {
	header.Del(ForwardToHeader)
	header.Del(SecretProviderHeader)
	header.Del(TemplateHeader)
}
