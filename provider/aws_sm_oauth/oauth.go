package aws_sm_oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func GetOauthRequest(jwtToken string, secretId string,
	oAuthClientId string, oAuthUrl *url.URL,
) *http.Request {
	formData := getFormData(oAuthClientId, jwtToken, secretId)
	r, _ := http.NewRequest(http.MethodPost, oAuthUrl.String(), strings.NewReader(formData.Encode()))
	headers := getHeaders()
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func GetAccessTokenFromResponse(response *http.Response) (token string, err error) {
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
