package server

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestServerUtils_MakeHasuraError(t *testing.T) {
	mockErrorMessage := "Error"
	expectedResultMap := map[string]interface{}{
		"message": mockErrorMessage,
		"extensions": map[string]string{
			"code": "hasura-error",
		},
	}
	expectedResult, _ := json.Marshal(expectedResultMap)
	actualResult := makeHasuraError(mockErrorMessage)
	if string(expectedResult) != actualResult {
		t.Fail()
	}
}

func TestServerUtils_GetUrlWithSchemeAndHost(t *testing.T) {
	testCases := map[string]string{
		"http://localhost:8080":                    "http://localhost:8080",
		"http://localhost:8080/path1/path2":        "http://localhost:8080",
		"http://localhost:8080?query1=test":        "http://localhost:8080",
		"http://localhost:8080/path?query1=test":   "http://localhost:8080",
		"https://www.example.org":                  "https://www.example.org",
		"https://www.example.org/path1/path2":      "https://www.example.org",
		"https://www.example.org?query1=test":      "https://www.example.org",
		"https://www.example.org/path?query1=test": "https://www.example.org",
	}
	for k, v := range testCases {
		expectedResult := v
		input, _ := url.Parse(k)
		actualResultParsed := getUrlWithSchemeAndHost(input)
		actualResult := actualResultParsed.String()
		if actualResult != expectedResult {
			t.Fatalf("Test case %s: expected %s but received %s", k, expectedResult, actualResult)
		}
	}
}

func TestServerUtils_ParseUrl(t *testing.T) {
	validUrls := []string{
		"http://localhost:8080",
		"http://localhost:8080/path1/path2",
		"http://localhost:8080?query1=test",
		"http://localhost:8080/path?query1=test",
		"https://www.example.org",
		"https://www.example.org/path1/path2",
		"https://www.example.org?query1=test",
		"https://www.example.org/path?query1=test",
	}
	invalidUrls := []string{
		"ab://localhost:8080",
		"http:/localhost:8080/path1/path2",
		"http//localhost:8080?query1=test",
		"http/localhost:8080/path?query1=test",
		"random_string",
		"https://",
		"https",
		":",
	}
	for _, v := range validUrls {
		_, err := parseUrl(v)
		if err != nil {
			t.Fatalf("For url %s: Expected error to be nil", v)
		}
	}
	for _, v := range invalidUrls {
		_, err := parseUrl(v)
		if err == nil {
			t.Fatalf("For url %s: Expected an error since url is invalid", v)
		}
	}
}
