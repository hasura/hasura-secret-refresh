package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

func getMockRequest(withUrl string, withHeaders map[string]string, t *testing.T) *http.Request {
	mockDefaultHeaders := map[string]string{
		"Content-Type":         "application/json",
		"X-Some-Custom-Header": "custom_value",
	}
	mockRequest, err := http.NewRequest("GET", withUrl, nil)
	for k, v := range mockDefaultHeaders {
		mockRequest.Header.Set(k, v)
	}
	if withHeaders != nil {
		for k, v := range withHeaders {
			mockRequest.Header.Set(k, v)
		}
	}
	if err != nil {
		t.Fatal("Unable to make mock request")
	}
	return mockRequest
}

type mockProvider struct{}
type mockFetcher struct {
	secretId string
}

func (f mockFetcher) FetchSecret() (string, error) {
	if f.secretId == "make_error" {
		return "", errors.New("error")
	}
	return "topsecretval", nil
}

func (_ mockProvider) SecretFetcher(header http.Header) (provider.SecretFetcher, error) {
	secretId := header.Get("X-Hasura-Secret-Id")
	if secretId == "" {
		return nil, fmt.Errorf("err")
	}
	return mockFetcher{
		secretId: secretId,
	}, nil
}

func (_ mockProvider) DeleteConfigHeaders(header *http.Header) {
	header.Del("X-Hasura-Secret-Id")
}

func TestGetRewriteDetails_WithMissingRequestConfig(t *testing.T) {
	mockRequest := getMockRequest("http://somehost", nil, t)
	rw := httptest.NewRecorder()
	providers := map[string]provider.HttpProvider{
		"mock_provider": mockProvider{},
	}
	_, _, _, _, ok := getRequestRewriteDetails(rw, mockRequest, providers, zerolog.Nop())
	if ok != false {
		t.Errorf("Expected 'ok' to be false")
	}
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status code to be %d but got %d", http.StatusBadRequest, rw.Code)
	}
}

func TestGetRewriteDetails_WithInvalidUrl(t *testing.T) {
	withHeaders := map[string]string{
		forwardToHeader:      "invalid_url",
		"X-Hasura-Secret-Id": "some_secret",
		secretProviderHeader: "mock_provider",
		templateHeader:       "Auth: Bearer ##secret##",
	}
	mockRequest := getMockRequest("http://somehost", withHeaders, t)
	rw := httptest.NewRecorder()
	providers := map[string]provider.HttpProvider{
		"mock_provider": mockProvider{},
	}
	_, _, _, _, ok := getRequestRewriteDetails(rw, mockRequest, providers, zerolog.Nop())
	if ok != false {
		t.Errorf("Expected 'ok' to be false")
	}
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status code to be %d but got %d", http.StatusBadRequest, rw.Code)
	}
}

func TestGetRewriteDetails_WithInvalidProvider(t *testing.T) {
	withHeaders := map[string]string{
		forwardToHeader:      "http://somehost",
		"X-Hasura-Secret-Id": "some_secret",
		secretProviderHeader: "mock_provider_random",
		templateHeader:       "Auth: Bearer ##secret##",
	}
	mockRequest := getMockRequest("http://somehost", withHeaders, t)
	rw := httptest.NewRecorder()
	providers := map[string]provider.HttpProvider{
		"mock_provider": mockProvider{},
	}
	_, _, _, _, ok := getRequestRewriteDetails(rw, mockRequest, providers, zerolog.Nop())
	if ok != false {
		t.Errorf("Expected 'ok' to be false")
	}
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status code to be %d but got %d", http.StatusBadRequest, rw.Code)
	}
}

func TestGetRewriteDetails_WithInvalidSecret(t *testing.T) {
	withHeaders := map[string]string{
		forwardToHeader:      "http://somehost",
		"X-Hasura-Secret-Id": "make_error",
		secretProviderHeader: "mock_provider",
		templateHeader:       "Auth: Bearer ##secret##",
	}
	mockRequest := getMockRequest("http://somehost", withHeaders, t)
	rw := httptest.NewRecorder()
	providers := map[string]provider.HttpProvider{
		"mock_provider": mockProvider{},
	}
	_, _, _, _, ok := getRequestRewriteDetails(rw, mockRequest, providers, zerolog.Nop())
	if ok != false {
		t.Errorf("Expected 'ok' to be false")
	}
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status code to be %d but got %d", http.StatusBadRequest, rw.Code)
	}
}

func TestGetRewriteDetails_WithMissingProviderConfig(t *testing.T) {
	withHeaders := map[string]string{
		forwardToHeader:      "http://somehost",
		secretProviderHeader: "mock_provider",
		templateHeader:       "Auth: Bearer ##secret##",
	}
	mockRequest := getMockRequest("http://somehost", withHeaders, t)
	rw := httptest.NewRecorder()
	providers := map[string]provider.HttpProvider{
		"mock_provider": mockProvider{},
	}
	_, _, _, _, ok := getRequestRewriteDetails(rw, mockRequest, providers, zerolog.Nop())
	if ok != false {
		t.Errorf("Expected 'ok' to be false")
	}
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status code to be %d but got %d", http.StatusBadRequest, rw.Code)
	}
}

func TestGetRewriteDetails_WithInvalidHeaderTemplate(t *testing.T) {
	withHeaders := map[string]string{
		forwardToHeader:      "http://somehost",
		"X-Hasura-Secret-Id": "secret123",
		secretProviderHeader: "mock_provider",
		templateHeader:       "Bearer ##secret##",
	}
	mockRequest := getMockRequest("http://somehost", withHeaders, t)
	rw := httptest.NewRecorder()
	providers := map[string]provider.HttpProvider{
		"mock_provider": mockProvider{},
	}
	_, _, _, _, ok := getRequestRewriteDetails(rw, mockRequest, providers, zerolog.Nop())
	if ok != false {
		t.Errorf("Expected 'ok' to be false")
	}
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status code to be %d but got %d", http.StatusBadRequest, rw.Code)
	}
}

func TestGetRewriteDetails_SuccessfulRequest(t *testing.T) {
	withHeaders := map[string]string{
		forwardToHeader:      "http://somehost",
		"X-Hasura-Secret-Id": "secret123",
		secretProviderHeader: "mock_provider",
		templateHeader:       "Auth: Bearer ##secret##",
	}
	mockRequest := getMockRequest("http://somehost", withHeaders, t)
	rw := httptest.NewRecorder()
	providers := map[string]provider.HttpProvider{
		"mock_provider": mockProvider{},
	}
	url, headerKey, headerVal, _, ok := getRequestRewriteDetails(rw,
		mockRequest, providers, zerolog.Nop())
	if ok != true {
		t.Errorf("Expected 'ok' to be true")
	}
	if rw.Code != http.StatusOK {
		t.Errorf("Expected status code to be %d but got %d", http.StatusOK, rw.Code)
	}
	if url.String() != withHeaders[forwardToHeader] {
		t.Errorf("Expected url to be %s but got %s", withHeaders[forwardToHeader], url.String())
	}
	if headerKey != "Auth" {
		t.Errorf("Expected header name to be 'Auth' but got %s", headerKey)
	}
	if headerVal != "Bearer topsecretval" {
		t.Errorf("Expected header name to be 'Bearer topsecretval' but got %s", headerVal)
	}
}

func TestRequestRewriter_HeadersAreRemoved(t *testing.T) {
	withHeaders := map[string]string{
		forwardToHeader:      "http://somehost",
		"X-Hasura-Secret-Id": "secret123",
		secretProviderHeader: "mock_provider",
		templateHeader:       "Auth: Bearer ##secret##",
	}
	mockHeaderKey, mockHeaderVal := "Auth", "Bearer topsecretval"
	mockUrl, _ := url.Parse("http://localhost:8080")
	mockRequest := getMockRequest("http://somehost", withHeaders, t)
	numInHeaders := len(mockRequest.Header)
	proxyRequest := httputil.ProxyRequest{
		In:  mockRequest,
		Out: mockRequest,
	}
	providerDeleteHeaders := func(header *http.Header) {
		header.Del("X-Hasura-Secret-Id")
	}
	rewriter := getRequestRewriter(mockUrl, mockHeaderKey, mockHeaderVal, providerDeleteHeaders, zerolog.Nop())
	rewriter(&proxyRequest)
	numOutHeaders := len(proxyRequest.Out.Header)
	if numOutHeaders != numInHeaders-3 {
		t.Fatalf("Expected exactly %d headers but received %d", numInHeaders-3, numOutHeaders)
	}
	for k, _ := range proxyRequest.Out.Header {
		_, found := withHeaders[k]
		if found {
			t.Errorf("Header %s should not have been present in the request", k)
		}
	}
	for k, _ := range mockRequest.Header {
		_, found := withHeaders[k]
		if found {
			t.Errorf("Header %s should not have been present in the request", k)
		}
		_, found = proxyRequest.Out.Header[k]
		if !found {
			t.Errorf("Expected to find header %s", k)
		}
	}
}

func TestRequestRewriter_OutGoingUrl(t *testing.T) {
	//map between incoming url to forward url
	testCases := []struct {
		incomingUrl  string // the url to which the proxy receives the request
		forwardToUrl string // the url to received in the X-Hasura-Forward-To header
		outgoingUrl  string // the url to which the request will be forwarded to
	}{
		{"http://localhost:8080", "http://somehost:8090", "http://somehost:8090/"},
		{"http://localhost:8080/path", "http://somehost:8090", "http://somehost:8090/path"},
		{"http://localhost:8080?query=test", "http://somehost:8090", "http://somehost:8090/?query=test"},
		{"http://localhost:8080/path?query=test", "http://somehost:8090", "http://somehost:8090/path?query=test"},
	}
	withHeaders := map[string]string{
		forwardToHeader:      "http://somehost",
		"X-Hasura-Secret-Id": "secret123",
		secretProviderHeader: "mock_provider",
		templateHeader:       "Auth: Bearer ##secret##",
	}
	mockHeaderKey, mockHeaderVal := "Auth", "Bearer topsecretval"
	providerDeleteHeaders := func(header *http.Header) {
		header.Del("X-Hasura-Secret-Id")
	}
	for _, v := range testCases {
		mockUrl, _ := url.Parse(v.forwardToUrl)
		mockRequest := getMockRequest(v.incomingUrl, withHeaders, t)
		proxyRequest := httputil.ProxyRequest{
			In:  mockRequest,
			Out: mockRequest,
		}
		rewriter := getRequestRewriter(mockUrl, mockHeaderKey, mockHeaderVal, providerDeleteHeaders, zerolog.Nop())
		rewriter(&proxyRequest)
		if proxyRequest.Out.URL.String() != v.outgoingUrl {
			t.Errorf("Expected URL to be %s but it was %s", v.outgoingUrl, proxyRequest.Out.URL.String())
		}
	}
}
