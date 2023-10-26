package aws_sm_oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

func getOauthRequest(jwtToken string, secretId string,
	oAuthClientId string, oAuthUrl *url.URL,
) (method string, formData url.Values, header http.Header) {
	formData = getFormData(oAuthClientId, jwtToken, secretId)
	method = http.MethodPost
	headers := getHeaders()
	header = http.Header{}
	for k, v := range headers {
		header.Set(k, v)
	}
	return
}

func getAccessTokenFromResponse(response *http.Response) (token string, err error) {
	defer response.Body.Close()
	responseJson := make(map[string]interface{})
	err = json.NewDecoder(response.Body).Decode(&responseJson)
	if err != nil {
		return "", fmt.Errorf("Error converting oauth response to json: %s", err)
	}
	_, ok := responseJson["access_token"]
	if !ok {
		return "", fmt.Errorf("Key 'access_token' not found in the response from oauth endpoint")
	}
	token, ok = responseJson["access_token"].(string)
	if !ok {
		return token, errors.New(fmt.Sprintf("Error converting token to string"))
	}
	return
}

func getFormData(oAuthClientId string, jwtToken string, secretId string) url.Values {
	formData := map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_id":             oAuthClientId,
		"client_assertion":      jwtToken,
		"resource":              secretId,
	}
	data := url.Values{}
	for k, v := range formData {
		data.Set(k, v)
	}
	return data
}

func getHeaders() map[string]string {
	return map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/x-www-form-url-encoded",
	}
}
