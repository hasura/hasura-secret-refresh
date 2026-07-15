package template

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
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
		name:           "json number",
		template:       "Bearer ##secret1.key## ##secret1.key2##",
		substituteWith: `{"key": "some_secret", "key2": 2}`,
		expected:       "Bearer some_secret 2",
	},
	{
		name:           "key not found",
		template:       "Bearer ##secret1.key## ##secret1.key2##",
		substituteWith: `{"key": "some_secret"}`,
		expected:       "Bearer some_secret",
	},
	{
		name:           "key not found 2",
		template:       "Bearer ##secret1.key## ##secret1.key2##",
		substituteWith: `{"key2": "2"}`,
		expected:       "Bearer  2",
	},
	{
		name:           "json template multiple types",
		template:       "Bearer ##secret1.key1## ##secret1.key2## ##secret1.three## ##secret1.point## ##secret1.array##",
		substituteWith: `{"key1": "one", "key2": 2, "three": true, "point": 1.5, "array": [1, true, "ok"]}`,
		expected:       "Bearer one 2 true 1.5 [1 true ok]",
	},
	{
		name:           "invalid json",
		template:       "Bearer ##secret1.key1## ##secret1.key2## ##secret1.three## ##secret1.point## ##secret1.array##",
		substituteWith: `{"key1": one", "key2": 2, "three": true, "point": 1.5, "array": [1, true, "ok"]}`,
		expected:       "Bearer",
	},
	{
		name:           "nested JSON",
		template:       "Bearer ##secret1.key.key##",
		substituteWith: `{"key": {"key": "key"}}`,
		expected:       "Bearer",
	},
}

func TestTemplate_GetKeysFromTemplates(t *testing.T) {
	for _, testCase := range testCases {
		template := Template{testCase.template, zerolog.Nop()}
		actual := template.Substitute(testCase.substituteWith)
		if strings.TrimSpace(testCase.expected) != strings.TrimSpace(actual) {
			t.Errorf("Test case - %s: Expected '%s' but got '%s'", testCase.name, testCase.expected, actual)
		}
	}
}

func TestTemplateDoesNotLeakSecretContentsInLogs(t *testing.T) {
	t.Run("malformed json reports position without payload", func(t *testing.T) {
		var logs bytes.Buffer
		logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
		template := Template{Templ: "Bearer ##secret1.token##", Logger: logger}

		actual := template.Substitute("{\n  \"token\": \"super-secret\",\n  \"broken\": [1,}\n")
		if strings.TrimSpace(actual) != "Bearer" {
			t.Fatalf("expected substitution to stop after parse failure, got %q", actual)
		}

		logOutput := logs.String()
		if strings.Contains(logOutput, "super-secret") {
			t.Fatalf("log output leaked secret contents: %s", logOutput)
		}
		if !strings.Contains(logOutput, "\"template_key\":\"secret1.token\"") {
			t.Fatalf("expected template key in log output, got %s", logOutput)
		}
		if !strings.Contains(logOutput, "\"line\":") || !strings.Contains(logOutput, "\"column\":") {
			t.Fatalf("expected line/column info in log output, got %s", logOutput)
		}
	})

	t.Run("lookup failures report key path without payload", func(t *testing.T) {
		tests := []struct {
			name           string
			template       string
			secret         string
			expectedLogMsg string
			expectedKey    string
		}{
			{
				name:           "missing key",
				template:       "Bearer ##secret1.missing##",
				secret:         `{"token":"super-secret"}`,
				expectedLogMsg: "Template key not found in secret JSON",
				expectedKey:    "secret1.missing",
			},
			{
				name:           "nested object",
				template:       "Bearer ##secret1.key.inner##",
				secret:         `{"key":{"inner":"super-secret"}}`,
				expectedLogMsg: "Nested JSON lookups are not supported in secrets",
				expectedKey:    "secret1.key.inner",
			},
		}

		for _, testCase := range tests {
			t.Run(testCase.name, func(t *testing.T) {
				var logs bytes.Buffer
				logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
				template := Template{Templ: testCase.template, Logger: logger}

				_ = template.Substitute(testCase.secret)

				logOutput := logs.String()
				if strings.Contains(logOutput, "super-secret") {
					t.Fatalf("log output leaked secret contents: %s", logOutput)
				}
				if !strings.Contains(logOutput, testCase.expectedLogMsg) {
					t.Fatalf("expected log message %q, got %s", testCase.expectedLogMsg, logOutput)
				}
				if !strings.Contains(logOutput, "\"template_key\":\""+testCase.expectedKey+"\"") {
					t.Fatalf("expected template key %q in log output, got %s", testCase.expectedKey, logOutput)
				}
			})
		}
	})
}
