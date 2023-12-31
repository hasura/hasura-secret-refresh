package server

import (
	"encoding/json"
	"fmt"
	"net/url"
)

/*
	Generates an error in the format supported by Hasura actions.
	Refer: https://hasura.io/docs/latest/actions/action-handlers/#returning-an-error-response
*/
func makeHasuraError(errorMsg string) string {
	jsonMap := map[string]interface{}{
		"message": errorMsg,
		"extensions": map[string]string{
			"code": "hasura-error",
		},
	}
	json, _ := json.Marshal(jsonMap)
	return string(json)
}

func getUrlWithSchemeAndHost(inpUrl *url.URL) (newUrl *url.URL) {
	newUrl = &url.URL{
		Scheme: inpUrl.Scheme,
		Host:   inpUrl.Host,
	}
	return
}

func parseUrl(input string) (parsedUrl *url.URL, err error) {
	parsedUrl, err = url.Parse(input)
	if err != nil {
		return
	}
	allowedSchemesSet := map[string]bool{
		"http":  true,
		"https": true,
	}
	_, allowed := allowedSchemesSet[parsedUrl.Scheme]
	if !allowed {
		return parsedUrl, fmt.Errorf("URL must contain a scheme 'http' or 'https'")
	}
	if parsedUrl.Host == "" {
		return parsedUrl, fmt.Errorf("URL must contain a host")
	}
	return
}
