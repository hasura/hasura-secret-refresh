package aws_sm_oauth

import (
	"net/http"

	requestconfig "github.com/hasura/hasura-secret-refresh/request_config"
)

type RequestConfig struct {
	CertificateSecretId string
	OAuthClientId       string
	BackendApiId        string
}

const (
	CertificateSecretIdHeader = "X-Hasura-Certificate-Id"
	OauthClientIdHeader       = "X-Hasura-Oauth-Client-Id"
	BackendApiIdHeader        = "X-Hasura-Backend-Id"
)

func GetRequestConfig(headers http.Header) (
	requestConfig RequestConfig, err error,
) {
	parseRequestConfigInput := []requestconfig.ParseRequestConfigInput{
		{
			HeaderName:   CertificateSecretIdHeader,
			UpdateConfig: func(headerVal string) { requestConfig.CertificateSecretId = headerVal },
		},
		{
			HeaderName:   OauthClientIdHeader,
			UpdateConfig: func(headerVal string) { requestConfig.OAuthClientId = headerVal },
		},
		{
			HeaderName:   BackendApiIdHeader,
			UpdateConfig: func(headerVal string) { requestConfig.BackendApiId = headerVal },
		},
	}
	err = requestconfig.ParseRequestConfig(headers, parseRequestConfigInput)
	if err != nil {
		return
	}
	return requestConfig, nil
}

func DeleteConfigHeaders(headers *http.Header) {
	headers.Del(CertificateSecretIdHeader)
	headers.Del(OauthClientIdHeader)
	headers.Del(BackendApiIdHeader)
	return
}
