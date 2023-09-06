package provider

import (
	"testing"
)

func TestTemplate_GetRequestConfig(t *testing.T) {
	mockHeaders := map[string]string{
		"X-Hasura-Forward-To":      "http://someurl.com",
		"X-Hasura-Secret-Id":       "some_secret_id",
		"X-Hasura-Secret-Provider": "some_provider_name",
		"X-Hasura-Secret-Header":   "Bearer ##secret##",
	}
	response, err := GetRequestConfig(mockHeaders)
	if err != nil {
		t.Fail()
	}
	if response.DestinationUrl != "http://someurl.com" ||
		response.SecretId != "some_secret_id" ||
		response.SecretProvider != "some_provider_name" ||
		response.HeaderTemplate != "Bearer ##secret##" {
		t.Fail()
	}
}

func TestTemplate_GetRequestConfigError(t *testing.T) {
	mockHeaders := map[string]string{
		"X-Hasura-Secret-Id":       "some_secret_id",
		"X-Hasura-Secret-Provider": "some_provider_name",
		"X-Hasura-Secret-Header":   "Bearer ##secret##",
	}
	_, err := GetRequestConfig(mockHeaders)
	if err == nil {
		t.Fail()
	}
}

func TestTemplate_IsRequestConfig(t *testing.T) {
	requestConfigHeaders := []string{
		"X-Hasura-Forward-To",
		"X-Hasura-Secret-Id",
		"X-Hasura-Secret-Provider",
		"X-Hasura-Secret-Header",
	}
	anyOtherHeaders := []string{
		"Authorization",
		"Cache-Control",
		"Content-Type",
		"Referer",
		"Some-Custom-Header",
	}
	for _, v := range requestConfigHeaders {
		response := IsRequestConfig(v)
		if response != true {
			t.Errorf("%s is a request config", v)
		}
	}
	for _, v := range anyOtherHeaders {
		response := IsRequestConfig(v)
		if response != false {
			t.Errorf("%s is not a request config", v)
		}
	}
}
