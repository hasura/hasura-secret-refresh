package aws_sm_oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-retryablehttp"
)

func GetOauthRequest(jwtToken string, secretId string,
	oAuthClientId string, oAuthUrl *url.URL,
) *retryablehttp.Request {
	formData := getFormData(oAuthClientId, jwtToken, secretId)
	r, _ := retryablehttp.NewRequest(http.MethodPost, oAuthUrl.String(), strings.NewReader(formData.Encode()))
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
		return
	}
	token, ok := responseJson["access_token"].(string)
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
