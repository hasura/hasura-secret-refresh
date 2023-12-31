package server

import (
	"testing"

	"github.com/rs/zerolog"
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
	{
		name:              "template with 2 secrets",
		template:          "Authorization: Bearer ##secret1## ##secret1##",
		substituteWith:    "some_secret",
		expectedHeaderKey: "Authorization",
		expectedHeaderVal: "Bearer some_secret some_secret",
		expectedIsErr:     false,
	},
	{
		name:              "json template simple",
		template:          "Authorization: Bearer ##secret1.key##",
		substituteWith:    `{"key": "some_secret"}`,
		expectedHeaderKey: "Authorization",
		expectedHeaderVal: "Bearer some_secret",
		expectedIsErr:     false,
	},
	{
		name:              "json template complex",
		template:          "Authorization: Bearer ##secret1.key## ##secret1.key2##",
		substituteWith:    `{"key": "some_secret", "key2": "2"}`,
		expectedHeaderKey: "Authorization",
		expectedHeaderVal: "Bearer some_secret 2",
		expectedIsErr:     false,
	},
	{
		name:              "number",
		template:          "Authorization: Bearer ##secret1.key## ##secret1.key2##",
		substituteWith:    `{"key": "some_secret", "key2": 2}`,
		expectedHeaderKey: "Authorization",
		expectedHeaderVal: "Bearer some_secret 2",
		expectedIsErr:     false,
	},
	{
		name:              "key not found",
		template:          "Authorization: Bearer ##secret1.key## ##secret1.key2##",
		substituteWith:    `{"key": "some_secret"}`,
		expectedHeaderKey: "Authorization",
		expectedHeaderVal: "Bearer some_secret ",
		expectedIsErr:     false,
	},
	{
		name:              "key not found 2",
		template:          "Authorization: Bearer ##secret1.key## ##secret1.key2##",
		substituteWith:    `{"key2": "2"}`,
		expectedHeaderKey: "Authorization",
		expectedHeaderVal: "Bearer  2",
		expectedIsErr:     false,
	},
}

func TestTemplate_GetKeysFromTemplates(t *testing.T) {
	for _, testCase := range testCases {
		headerKey, headerVal, err := getHeaderFromTemplate(testCase.template, testCase.substituteWith, zerolog.Nop())
		if testCase.expectedIsErr && err == nil {
			t.Errorf("Expected error in test %s but got no error", testCase.name)
		}
		if testCase.expectedIsErr && err != nil {
			continue
		}
		if testCase.expectedHeaderKey != headerKey {
			t.Errorf("Expected %s as header key but got %s", testCase.expectedHeaderKey, headerKey)
		}
		if testCase.expectedHeaderVal != headerVal {
			t.Errorf("Expected %s as header val but got %s", testCase.expectedHeaderVal, headerVal)
		}
	}
}
