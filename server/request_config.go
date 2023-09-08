package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type RequestConfig struct {
	DestinationUrl string
	SecretId       string
	SecretProvider string
	HeaderTemplate string
}

type RequestConfigItem struct {
	UpdateRequestConfig func(*RequestConfig, string)
}

const (
	ForwardToHeader      = "X-Hasura-Forward-To"
	SecretIdHeader       = "X-Hasura-Secret-Id"
	SecretProviderHeader = "X-Hasura-Secret-Provider"
	TemplateHeader       = "X-Hasura-Secret-Header"
)

// map from header name to request config item
var RequestConfigs = map[string]RequestConfigItem{
	ForwardToHeader: {
		UpdateRequestConfig: func(config *RequestConfig, val string) {
			config.DestinationUrl = val
		},
	},
	SecretIdHeader: {
		UpdateRequestConfig: func(config *RequestConfig, val string) {
			config.SecretId = val
		},
	},
	SecretProviderHeader: {
		UpdateRequestConfig: func(config *RequestConfig, val string) {
			config.SecretProvider = val
		},
	},
	TemplateHeader: {
		UpdateRequestConfig: func(config *RequestConfig, val string) {
			config.HeaderTemplate = val
		},
	},
}

func GetRequestConfig(headers http.Header) (
	requestConfig RequestConfig, err error,
) {
	notFoundHeaders := make([]string, 0, 0)
	for k, v := range RequestConfigs {
		val := headers.Get(k)
		if val == "" {
			notFoundHeaders = append(notFoundHeaders, k)
		}
		v.UpdateRequestConfig(&requestConfig, val)
	}
	if len(notFoundHeaders) != 0 {
		notFoundHeadersString := strings.Join(notFoundHeaders, ", ")
		return requestConfig, errors.New(fmt.Sprintf("Header(s) %s not found in request", notFoundHeadersString))
	}
	return requestConfig, nil
}

func IsRequestConfig(headerName string) bool {
	_, found := RequestConfigs[headerName]
	return found
}
