package provider

import (
	"errors"
	"fmt"
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

// map from header name to request config item
var requestConfigs = map[string]RequestConfigItem{
	"X-Hasura-Forward-To": {
		UpdateRequestConfig: func(config *RequestConfig, val string) {
			config.DestinationUrl = val
		},
	},
	"X-Hasura-Secret-Id": {
		UpdateRequestConfig: func(config *RequestConfig, val string) {
			config.SecretId = val
		},
	},
	"X-Hasura-Secret-Provider": {
		UpdateRequestConfig: func(config *RequestConfig, val string) {
			config.SecretProvider = val
		},
	},
	"X-Hasura-Secret-Header": {
		UpdateRequestConfig: func(config *RequestConfig, val string) {
			config.HeaderTemplate = val
		},
	},
}

func GetRequestConfig(headers map[string]string) (
	requestConfig RequestConfig, err error,
) {
	for k, v := range requestConfigs {
		val, ok := headers[k]
		if !ok {
			return requestConfig, errors.New(fmt.Sprintf("Header %s not found in request", k))
		}
		v.UpdateRequestConfig(&requestConfig, val)
	}
	return
}

func IsRequestConfig(headerName string) bool {
	_, found := requestConfigs[headerName]
	return found
}
