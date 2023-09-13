package requestconfig

import (
	"net/http"
	"testing"
)

type MockRequestConfig struct {
	DestinationUrl string
	SecretProvider string
	HeaderTemplate string
}

func TestRequestConfig_GetRequestConfig(t *testing.T) {
	mockHeaders := http.Header{
		"X-Hasura-Forward-To":      {"http://someurl.com"},
		"X-Hasura-Secret-Provider": {"some_provider_name"},
		"X-Hasura-Secret-Header":   {"Bearer ##secret##"},
	}
	mockRequestConfig := MockRequestConfig{}
	parseRequestConfigInput := []ParseRequestConfigInput{
		{
			HeaderName:   "X-Hasura-Forward-To",
			UpdateConfig: func(headerVal string) { mockRequestConfig.DestinationUrl = headerVal },
		},
		{
			HeaderName:   "X-Hasura-Secret-Provider",
			UpdateConfig: func(headerVal string) { mockRequestConfig.SecretProvider = headerVal },
		},
		{
			HeaderName:   "X-Hasura-Secret-Header",
			UpdateConfig: func(headerVal string) { mockRequestConfig.HeaderTemplate = headerVal },
		},
	}
	err := ParseRequestConfig(mockHeaders, parseRequestConfigInput)
	if err != nil {
		t.Fail()
	}
	if mockRequestConfig.DestinationUrl != "http://someurl.com" ||
		mockRequestConfig.SecretProvider != "some_provider_name" ||
		mockRequestConfig.HeaderTemplate != "Bearer ##secret##" {
		t.Fail()
	}
}

func TestRequestConfig_GetRequestConfigError(t *testing.T) {
	mockHeaders := http.Header{
		"X-Hasura-Forward-To":      {"http://someurl.com"},
		"X-Hasura-Secret-Provider": {"some_provider_name"},
	}
	mockRequestConfig := MockRequestConfig{}
	parseRequestConfigInput := []ParseRequestConfigInput{
		{
			HeaderName:   "X-Hasura-Forward-To",
			UpdateConfig: func(headerVal string) { mockRequestConfig.DestinationUrl = headerVal },
		},
		{
			HeaderName:   "X-Hasura-Secret-Provider",
			UpdateConfig: func(headerVal string) { mockRequestConfig.SecretProvider = headerVal },
		},
		{
			HeaderName:   "X-Hasura-Secret-Header",
			UpdateConfig: func(headerVal string) { mockRequestConfig.HeaderTemplate = headerVal },
		},
	}
	err := ParseRequestConfig(mockHeaders, parseRequestConfigInput)
	if err == nil {
		t.Fail()
	}
}
