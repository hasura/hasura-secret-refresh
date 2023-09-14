package aws_sm_oauth

import (
	"net/http"
	"testing"
)

func TestRequestConfig_GetRequestConfig(t *testing.T) {
	mockHeaders := http.Header{
		"X-Hasura-Certificate-Id":  {"some_secret_id"},
		"X-Hasura-Oauth-Client-Id": {"some_oauth_id"},
		"X-Hasura-Backend-Id":      {"some_backend_id"},
	}
	response, err := GetRequestConfig(mockHeaders)
	if err != nil {
		t.Fail()
	}
	if response.CertificateSecretId != "some_secret_id" {
		t.Fail()
	}
	if response.BackendApiId != "some_backend_id" {
		t.Fail()
	}
	if response.OAuthClientId != "some_oauth_id" {
		t.Fail()
	}
}

func TestRequestConfig_GetRequestConfigError(t *testing.T) {
	mockHeaders := http.Header{
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
		"X-Hasura-Certificate-Id":  {"some_secret_id"},
		"X-Hasura-Oauth-Client-Id": {"some_oauth_id"},
		"X-Hasura-Backend-Id":      {"some_backend_id"},
		"X-Some-Other-Header":      {"some_other_val"},
	}
	DeleteConfigHeaders(&mockHeaders)
	if mockHeaders.Get("X-Hasura-Certificate-Id") != "" {
		t.Fatalf("Header %s not deleted", "X-Hasura-Certificate-Id")
	}
	if mockHeaders.Get("X-Hasura-Oauth-Client-Id") != "" {
		t.Fatalf("Header %s not deleted", "X-Hasura-Oauth-Client-Id")
	}
	if mockHeaders.Get("X-Hasura-Backend-Id") != "" {
		t.Fatalf("Header %s not deleted", "X-Hasura-Backend-Id")
	}
	if mockHeaders.Get("X-Some-Other-Header") != "some_other_val" {
		t.Fatalf("Header %s was affected", "X-Some-Other-Header")
	}
}
