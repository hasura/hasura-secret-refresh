package provider

import "errors"

type RequestConfig struct {
	DestinationUrl string
	SecretId       string
	SecretProvider string
	HeaderTemplate string
}

func GetRequestConfig(headers map[string]string) (
	requestConfig RequestConfig, err error,
) {
	val, ok := headers["X-Proxy-Url"]
	if !ok {
		return requestConfig, errors.New("Header X-Proxy-Url not found in request")
	}
	requestConfig.DestinationUrl = val
	val, ok = headers["X-Proxy-Secret-Id"]
	if !ok {
		return requestConfig, errors.New("Header X-Proxy-Secret-Id not found in request")
	}
	requestConfig.SecretId = val
	val, ok = headers["X-Proxy-Secret-Provider"]
	if !ok {
		return requestConfig, errors.New("Header X-Proxy-Secret-Provider not found in request")
	}
	requestConfig.SecretProvider = val
	val, ok = headers["X-Proxy-Header-Template"]
	if !ok {
		return requestConfig, errors.New("Header X-Proxy-Header-Template not found in request")
	}
	requestConfig.HeaderTemplate = val
	return
}

func IsRequestConfig(headerName string) bool {
	requestConfigsSet := map[string]bool{
		"X-Proxy-Url":             true,
		"X-Proxy-Secret-Id":       true,
		"X-Proxy-Secret-Provider": true,
		"X-Proxy-Header-Template": true,
	}
	_, ok := requestConfigsSet[headerName]
	return ok
}
