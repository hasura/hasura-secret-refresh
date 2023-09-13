package aws_sm_oauth

import (
	"net/http"

	requestconfig "github.com/hasura/hasura-secret-refresh/request_config"
)

type RequestConfig struct {
	SecretId string
}

const (
	SecretIdHeader = "X-Hasura-Secret-Id"
)

func GetRequestConfig(headers http.Header) (
	requestConfig RequestConfig, err error,
) {
	parseRequestConfigInput := []requestconfig.ParseRequestConfigInput{
		{
			HeaderName:   SecretIdHeader,
			UpdateConfig: func(headerVal string) { requestConfig.SecretId = headerVal },
		},
	}
	err = requestconfig.ParseRequestConfig(headers, parseRequestConfigInput)
	if err != nil {
		return
	}
	return requestConfig, nil
}

func DeleteConfigHeaders(headers *http.Header) {
	headers.Del(SecretIdHeader)
	return
}
