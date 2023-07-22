package process_secrets

import (
	"testing"
)

type mockSecretsStore struct{}

func (_ mockSecretsStore) FetchSecrets(keys []string) (map[string]string, error) {
	result := make(map[string]string)
	mockSecrets := map[string]string{
		"secret1": "secret1val",
		"secret2": "secret2val",
		"secret3": "secret3val",
	}
	for _, key := range keys {
		result[key] = mockSecrets[key]
	}
	return result, nil
}

func TestModifyHeaders_SubstituteSecret(t *testing.T) {
	mockSecretsStore := mockSecretsStore{}
	var tests = []struct {
		Headers  map[string]string
		Expected map[string]string
	}{
		{
			Headers:  map[string]string{"Authorization": "Bearer ##secret1##"},
			Expected: map[string]string{"Authorization": "Bearer secret1val"},
		},
		{
			Headers:  map[string]string{"Authorization": "##secret1##"},
			Expected: map[string]string{"Authorization": "secret1val"},
		},
		{
			Headers:  map[string]string{"Authorization": "Bearer ##secret1## ##secret1##"},
			Expected: map[string]string{"Authorization": "Bearer secret1val secret1val"},
		},
		{
			Headers:  map[string]string{"Authorization": "Bearer ##secret2## ##secret1##"},
			Expected: map[string]string{"Authorization": "Bearer secret2val secret1val"},
		},
		{
			Headers:  map[string]string{"Content-Type": "application/json"},
			Expected: map[string]string{"Content-Type": "application/json"},
		},
		{
			Headers:  map[string]string{"Content-Type": "application/json", "Authorization": "Bearer ##secret1##"},
			Expected: map[string]string{"Content-Type": "application/json", "Authorization": "Bearer secret1val"},
		},
	}
	for i, test := range tests {
		actualResult, _ := GetChangedHeaders(test.Headers, mockSecretsStore)
		for header, _ := range test.Headers {
			actualHeaderVal, found := actualResult[header]
			expectedHeaderVal := test.Expected[header]
			if !found {
				t.Errorf("In test %d: Header %s not found", i, header)
			}
			if actualHeaderVal != expectedHeaderVal {
				t.Errorf("In test %d: Header value %s does not match %s for header %s", i, actualHeaderVal, expectedHeaderVal, header)
			}
		}
	}
}
