package server

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

type mockTransport struct {
	requestValidation func(*http.Request)
}

func (t mockTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	if t.requestValidation != nil {
		t.requestValidation(req)
	}
	body := `{"someField": 123}`
	headers := make(http.Header, 0)
	headers["some_custom_header_in_response"] = []string{"some_value_123"}
	response := &http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          ioutil.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
		Request:       req,
		Header:        headers,
	}
	return response, nil
}

func TestEndpoint(t *testing.T) {
	config := Config{}
	config.Providers = make(map[string]provider.HttpProvider)
	config.Providers["mock_provider"] = mockProvider{}
	server := Create(config, zerolog.Nop())
	server.reverseProxy = func(rewrite rewriteRequest) httputil.ReverseProxy {
		return httputil.ReverseProxy{
			Transport: mockTransport{
				requestValidation: func(req *http.Request) {
					headers := req.Header
					removedHeaders := []string{
						headers.Get(forwardToHeader),
						headers.Get("X-Hasura-Secret-Id"),
						headers.Get(templateHeader),
						headers.Get(secretProviderHeader),
					}
					for _, v := range removedHeaders {
						if v != "" {
							t.Errorf("Unexpected header: %v", removedHeaders)
						}
					}
					if headers.Get("Content-Type") != "application/json" {
						t.Errorf("Expected header and val not found. Found %s: %s",
							"Content-Type", headers.Get("Content-Type"),
						)
					}
					if headers.Get("X-Some-Custom-Header") != "custom_value" {
						t.Errorf("Expected header and val not found. Found %s: %s",
							"X-Some-Custom-Header", headers.Get("custom_value"),
						)
					}
					if req.URL.String() != "http://somehost/test" {
						t.Errorf("Host is invalid. Received %s", req.URL.String())
					}
				},
			},
			Rewrite: rewrite,
		}
	}
	withHeaders := map[string]string{
		forwardToHeader:      "http://somehost",
		"X-Hasura-Secret-Id": "secret123",
		secretProviderHeader: "mock_provider",
		templateHeader:       "Auth: Bearer ##secret##",
	}
	mockRequest := getMockRequest("http://proxyserver/test", withHeaders, t)
	rw := httptest.NewRecorder()
	server.ServeHTTP(rw, mockRequest)
	if rw.Code != http.StatusOK {
		t.Errorf("Expected status code to be %d but got %d", http.StatusOK, rw.Code)
	}
	if rw.Header().Get("some_custom_header_in_response") != "some_value_123" {
		t.Errorf("Expected header not found in response. Found '%s' instead", rw.Header().Get("some_custom_header_in_response"))
	}
	respJson := make(map[string]interface{})
	err := json.NewDecoder(rw.Body).Decode(&respJson)
	if err != nil {
		t.Errorf("Error decoding json: %s", err)
	}
	someField := respJson["someField"].(float64)
	if someField != 123 {
		t.Errorf("Unexpected value in body: %v", respJson["someField"])
	}
}

func TestEndpoint_Invalid(t *testing.T) {
	config := Config{}
	config.Providers = make(map[string]provider.HttpProvider)
	config.Providers["mock_provider"] = mockProvider{}
	server := Create(config, zerolog.Nop())
	server.reverseProxy = func(rewrite rewriteRequest) httputil.ReverseProxy {
		return httputil.ReverseProxy{
			Transport: mockTransport{},
			Rewrite:   rewrite,
		}
	}
	withHeaders := map[string]string{
		forwardToHeader:      "http://somehost",
		secretProviderHeader: "mock_provider",
		templateHeader:       "Auth: Bearer ##secret##",
	}
	mockRequest := getMockRequest("http://proxyserver/test", withHeaders, t)
	rw := httptest.NewRecorder()
	server.ServeHTTP(rw, mockRequest)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status code to be %d but got %d", http.StatusOK, rw.Code)
	}
}
