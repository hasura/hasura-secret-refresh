package server

import (
	"net/http"
	"testing"
)

func TestRequestConfig_GetRequestConfig(t *testing.T) {
	mockHeaders := http.Header{
		"X-Hasura-Forward-To":      {"http://someurl.com"},
		"X-Hasura-Secret-Id":       {"some_secret_id"},
		"X-Hasura-Secret-Provider": {"some_provider_name"},
		"X-Hasura-Secret-Header":   {"Bearer ##secret##"},
	}
	response, err := GetRequestConfig(mockHeaders)
	if err != nil {
		t.Fail()
	}
	if response.DestinationUrl != "http://someurl.com" ||
		response.SecretProvider != "some_provider_name" ||
		response.HeaderTemplate != "Bearer ##secret##" {
		t.Fail()
	}
}

func TestRequestConfig_GetRequestConfigError(t *testing.T) {
	mockHeaders := http.Header{
		"X-Hasura-Secret-Id":       {"some_secret_id"},
		"X-Hasura-Secret-Provider": {"some_provider_name"},
		"X-Hasura-Secret-Header":   {"Bearer ##secret##"},
	}
	_, err := GetRequestConfig(mockHeaders)
	if err == nil {
		t.Fail()
	}
}

func TestRequestConfig_DeleteHeader(t *testing.T) {
	mockHeaders := http.Header{
		"X-Hasura-Secret-Provider": {"some_provider_name"},
		"X-Hasura-Secret-Header":   {"Bearer ##secret##"},
		"X-Some-Other-Header":      {"some_other_val"},
	}
	DeleteConfigHeaders(&mockHeaders)
	if mockHeaders.Get("X-Hasura-Secret-Provider") != "" {
		t.Fatalf("Header %s not deleted", "X-Hasura-Secret-Provider")
	}
	if mockHeaders.Get("X-Hasura-Secret-Header") != "" {
		t.Fatalf("Header %s not deleted", "X-Hasura-Secret-Header")
	}
	if mockHeaders.Get("X-Some-Other-Header") != "some_other_val" {
		t.Fatalf("Header %s was affected", "X-Some-Other-Header")
	}
}
