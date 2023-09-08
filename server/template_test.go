package server

import (
	"testing"
)

type testCase struct {
	name              string
	template          string
	substituteWith    string
	expectedHeaderKey string
	expectedHeaderVal string
	expectedIsErr     bool
}

var testCases = []testCase{
	{
		name:              "simple template",
		template:          "Authorization: Bearer ##secret1##",
		substituteWith:    "some_secret",
		expectedHeaderKey: "Authorization",
		expectedHeaderVal: "Bearer some_secret",
		expectedIsErr:     false,
	},
	{
		name:              "template with just secret",
		template:          "Authorization: Bearer ##secret1##",
		substituteWith:    "some_secret",
		expectedHeaderKey: "Authorization",
		expectedHeaderVal: "Bearer some_secret",
		expectedIsErr:     false,
	},
	{
		name:              "invalid template",
		template:          "some string",
		substituteWith:    "some_secret",
		expectedHeaderKey: "",
		expectedHeaderVal: "",
		expectedIsErr:     true,
	},
}

func TestTemplate_GetKeysFromTemplates(t *testing.T) {
	for _, testCase := range testCases {
		headerKey, headerVal, err := GetHeaderFromTemplate(testCase.template, testCase.substituteWith)
		if testCase.expectedIsErr && err == nil {
			t.Errorf("Expected error in test %s but got no error", testCase.name)
		}
		if testCase.expectedIsErr {
			return
		}
		if testCase.expectedHeaderKey != headerKey {
			t.Errorf("Expected %s as header key but got %s", testCase.expectedHeaderKey, headerKey)
		}
		if testCase.expectedHeaderVal != headerVal {
			t.Errorf("Expected %s as header val but got %s", testCase.expectedHeaderVal, headerVal)
		}
	}
}
