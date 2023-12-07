package template

import (
	"testing"
)

type testCase struct {
	name           string
	template       string
	substituteWith string
	expected       string
}

var testCases = []testCase{
	{
		name:           "simple template",
		template:       "Bearer ##secret1##",
		substituteWith: "some_secret",
		expected:       "Bearer some_secret",
	},
	{
		name:           "template with just secret",
		template:       "Bearer ##secret1##",
		substituteWith: "some_secret",
		expected:       "Bearer some_secret",
	},
	{
		name:           "invalid template",
		template:       "some string",
		substituteWith: "some_secret",
		expected:       "some string",
	},
	{
		name:           "template with 2 secrets",
		template:       "Bearer ##secret1## ##secret1##",
		substituteWith: "some_secret",
		expected:       "Bearer some_secret some_secret",
	},
	{
		name:           "json template simple",
		template:       "Bearer ##secret1.key##",
		substituteWith: `{"key": "some_secret"}`,
		expected:       "Bearer some_secret",
	},
	{
		name:           "json template complex",
		template:       "Bearer ##secret1.key## ##secret1.key2##",
		substituteWith: `{"key": "some_secret", "key2": "2"}`,
		expected:       "Bearer some_secret 2",
	},
	{
		name:           "invalid json",
		template:       "Bearer ##secret1.key## ##secret1.key2##",
		substituteWith: `{"key": "some_secret", "key2": 2}`,
		expected:       "Bearer some_secret 2",
	},
	{
		name:           "key not found",
		template:       "Bearer ##secret1.key## ##secret1.key2##",
		substituteWith: `{"key": "some_secret"}`,
		expected:       "Bearer some_secret ",
	},
	{
		name:           "key not found 2",
		template:       "Bearer ##secret1.key## ##secret1.key2##",
		substituteWith: `{"key2": "2"}`,
		expected:       "Bearer  2",
	},
}

func TestTemplate_GetKeysFromTemplates(t *testing.T) {
	for _, testCase := range testCases {
		template := Template(testCase.template)
		actual := template.Substitute(testCase.substituteWith)
		if testCase.expected != actual {
			t.Errorf("Test case - %s: Expected '%s' but got '%s'", testCase.name, testCase.expected, actual)
		}
	}
}
