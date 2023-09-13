package aws_secrets_manager

import (
	"net/http"
	"testing"
)

func TestRequestConfig_GetRequestConfig(t *testing.T) {
	mockHeaders := http.Header{
		"X-Hasura-Secret-Id": {"some_secret_id"},
	}
	response, err := GetRequestConfig(mockHeaders)
	if err != nil {
		t.Fail()
	}
	if response.SecretId != "some_secret_id" {
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
		"X-Hasura-Secret-Id":  {"some_secret_id"},
		"X-Some-Other-Header": {"some_other_val"},
	}
	DeleteConfigHeaders(&mockHeaders)
	if mockHeaders.Get("X-Hasura-Secret-Id") != "" {
		t.Fatalf("Header %s not deleted", "X-Hasura-Secret-Id")
	}
	if mockHeaders.Get("X-Some-Other-Header") != "some_other_val" {
		t.Fatalf("Header %s was affected", "X-Some-Other-Header")
	}
}
