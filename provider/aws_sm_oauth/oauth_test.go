package aws_sm_oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestOauth_OauthRequest(t *testing.T) {
	mockJwtToken := "mock_jwt_token"
	mockSecretId := "mock_secret_id"
	mockOauthClientId := "mock_oauth_client_id"
	mockOAuthUrl, _ := url.Parse("http://oauth.com/token")
	request := GetOauthRequest(mockJwtToken, mockSecretId, mockOauthClientId, mockOAuthUrl)
	if request.Method != http.MethodPost {
		t.Errorf("Expected method to be %s but got %s", http.MethodPost, http.MethodGet)
	}
	request.ParseForm()
	expectedGrantType := "client_credentials"
	grantType := request.Form.Get("grant_type")
	if grantType != expectedGrantType {
		t.Errorf("Expected grant_type to be %s but received %s", expectedGrantType, grantType)
	}
	expectedClientAssertionType := "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	clientAssertionType := request.Form.Get("client_assertion_type")
	if clientAssertionType != expectedClientAssertionType {
		t.Errorf("Expected client_assertion_type to be %s but received %s", expectedClientAssertionType, clientAssertionType)
	}
	expectedClientId := mockOauthClientId
	clientId := request.Form.Get("client_id")
	if clientId != expectedClientId {
		t.Errorf("Expected client_id to be %s but received %s", expectedClientId, clientId)
	}
	expectedClientAssertion := mockJwtToken
	clientAssertion := request.Form.Get("client_assertion")
	if clientAssertion != expectedClientAssertion {
		t.Errorf("Expected client_assertion to be %s but received %s", expectedClientAssertion, clientAssertion)
	}
	expectedResource := mockSecretId
	resource := request.Form.Get("resource")
	if resource != expectedResource {
		t.Errorf("Expected resource to be %s but received %s", expectedResource, resource)
	}
	if len(request.Form) != 5 {
		t.Errorf("Unexpected form data found in request")
	}
	if request.URL.String() != mockOAuthUrl.String() {
		t.Errorf("Expected url %s but received %s", mockOAuthUrl.String(), request.URL.String())
	}
	if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("Unexpected value '%s' in header Content-Type", request.Header.Get("Content-Type"))
	}

	if request.Header.Get("Accept") != "application/x-www-form-url-encoded" {
		t.Errorf("Unexpected value '%s' in header Accept", request.Header.Get("Accept"))
	}
	if len(request.Header) != 2 {
		t.Errorf("Unexpected values in header")
	}
}

func TestOauth_GetAccessToken(t *testing.T) {
	mockResponse := httptest.NewRecorder()
	mockResponse.Header().Set("Content-Type", "application/json")
	jsonBody := map[string]interface{}{
		"access_token": "token123",
		"token_type":   "bearer",
		"expires_in":   43200,
	}
	json.NewEncoder(mockResponse).Encode(jsonBody)
	response := mockResponse.Result()
	token, err := GetAccessTokenFromResponse(response)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if token != "token123" {
		t.Fatalf("Expected token to be '%s' but received %s", "token123", token)
	}
}

func TestOauth_GetAccessTokenInvalidResponse(t *testing.T) {
	mockResponse := httptest.NewRecorder()
	mockResponse.Header().Set("Content-Type", "application/json")
	json.NewEncoder(mockResponse).Encode("")
	invalidJsonResponse := mockResponse.Result()
	_, err := GetAccessTokenFromResponse(invalidJsonResponse)
	if err == nil {
		t.Fatalf("Expected error because the body was an invalid json")
	}

	mockResponse = httptest.NewRecorder()
	mockResponse.Header().Set("Content-Type", "application/json")
	jsonBody := map[string]interface{}{
		"access_token": 123,
		"token_type":   "bearer",
		"expires_in":   43200,
	}
	json.NewEncoder(mockResponse).Encode(jsonBody)
	invalidTypeResponse := mockResponse.Result()
	_, err = GetAccessTokenFromResponse(invalidTypeResponse)
	if err == nil {
		t.Fatalf("Expected error because the type of token was invalid")
	}
}
