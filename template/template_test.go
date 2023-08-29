package process_secrets

import (
	"testing"
)

type testCase struct {
	name                    string
	templates               map[TemplateKey]Template
	expectedKeys            []SecretKey
	expectedApplied         map[TemplateKey]string
	expectedKeysPerTemplate map[TemplateKey][]SecretKey
}

func getDefaultTestCases(withTestCases []testCase) (testCases []testCase) {
	testCases = []testCase{
		{
			name:                    "one template with templated secret",
			templates:               map[TemplateKey]Template{"Authorization": "Bearer ##secret1##"},
			expectedKeys:            []SecretKey{"secret1"},
			expectedApplied:         map[TemplateKey]string{"Authorization": "Bearer secret1val"},
			expectedKeysPerTemplate: map[TemplateKey][]SecretKey{"Authorization": []SecretKey{"secret1"}},
		},
		{
			name:                    "one template with just secret",
			templates:               map[TemplateKey]Template{"Authorization": "##secret1##"},
			expectedKeys:            []SecretKey{"secret1"},
			expectedApplied:         map[TemplateKey]string{"Authorization": "secret1val"},
			expectedKeysPerTemplate: map[TemplateKey][]SecretKey{"Authorization": []SecretKey{"secret1"}},
		},
		{
			name:                    "one template with repeated secret",
			templates:               map[TemplateKey]Template{"Authorization": "Bearer ##secret1## ##secret1##"},
			expectedKeys:            []SecretKey{"secret1"},
			expectedApplied:         map[TemplateKey]string{"Authorization": "Bearer secret1val secret1val"},
			expectedKeysPerTemplate: map[TemplateKey][]SecretKey{"Authorization": []SecretKey{"secret1"}},
		},
		{
			name:                    "one template with two different secrets",
			templates:               map[TemplateKey]Template{"Authorization": "Bearer ##secret2## ##secret1##"},
			expectedKeys:            []SecretKey{"secret2", "secret1"},
			expectedApplied:         map[TemplateKey]string{"Authorization": "Bearer secret2val secret1val"},
			expectedKeysPerTemplate: map[TemplateKey][]SecretKey{"Authorization": []SecretKey{"secret1", "secret2"}},
		},
		{
			name:                    "one template with no secrets",
			templates:               map[TemplateKey]Template{"Content-Type": "application/json"},
			expectedKeys:            []SecretKey{},
			expectedApplied:         map[TemplateKey]string{"Content-Type": "application/json"},
			expectedKeysPerTemplate: map[TemplateKey][]SecretKey{"Content-Type": []SecretKey{}},
		},
		{
			name:                    "two template with and without secret",
			templates:               map[TemplateKey]Template{"Content-Type": "application/json", "Authorization": "Bearer ##secret1##"},
			expectedKeys:            []SecretKey{"secret1"},
			expectedApplied:         map[TemplateKey]string{"Content-Type": "application/json", "Authorization": "Bearer secret1val"},
			expectedKeysPerTemplate: map[TemplateKey][]SecretKey{"Authorization": []SecretKey{"secret1"}, "Content-Type": []SecretKey{}},
		},
	}
	if withTestCases != nil {
		for _, v := range withTestCases {
			testCases = append(testCases, v)
		}
	}
	return
}

func getDefaultMockSecrets(withMockSecrets map[SecretKey]Secret) (mockSecrets map[SecretKey]Secret) {
	mockSecrets = map[SecretKey]Secret{
		"secret1": "secret1val",
		"secret2": "secret2val",
		"secret3": "secret3val",
	}
	if withMockSecrets != nil {
		for k, v := range withMockSecrets {
			mockSecrets[k] = v
		}
	}
	return
}

func TestTemplate_GetKeysFromTemplates(t *testing.T) {
	testCases := getDefaultTestCases(nil)
	for _, testCase := range testCases {
		actualKeys := GetUniqueKeysFromTemplates(testCase.templates)
		if len(actualKeys) != len(testCase.expectedKeys) {
			t.Errorf("For test %s, length %d and %d does not match", testCase.name, len(actualKeys), len(testCase.expectedKeys))
		}

		uniqueKeys := make(map[SecretKey]bool)
		for _, v := range actualKeys {
			uniqueKeys[v] = true
		}
		for _, key := range testCase.expectedKeys {
			if _, ok := uniqueKeys[key]; !ok {
				t.Errorf("For test %s, key %s not returned", testCase.name, string(key))
			}
		}
	}
}

func TestTemplate_GetKeysFromTemplate(t *testing.T) {
	testCases := getDefaultTestCases(nil)
	templateToKeys := make(map[Template][]SecretKey)
	for _, i := range testCases {
		for k, v := range i.templates {
			templateToKeys[v] = i.expectedKeysPerTemplate[k]
		}
	}
	for template, expectedKeys := range templateToKeys {
		actualKeys := GetUniqueKeysFromTemplate(template)
		if len(actualKeys) != len(expectedKeys) {
			t.Errorf("For template %s, length %d and %d does not match", template, len(actualKeys), len(expectedKeys))
		}

		uniqueKeys := make(map[SecretKey]bool)
		for _, v := range actualKeys {
			uniqueKeys[v] = true
		}
		for _, key := range expectedKeys {
			if _, ok := uniqueKeys[key]; !ok {
				t.Errorf("For template %s, key %s not returned", template, string(key))
			}
		}
	}
}

func TestTemplate_ApplyTemplates(t *testing.T) {
	testCases := getDefaultTestCases(nil)
	secrets := getDefaultMockSecrets(nil)
	for _, testCase := range testCases {
		actualResult := ApplyTemplates(testCase.templates, secrets)
		if len(actualResult) != len(testCase.expectedApplied) {
			t.Errorf("For test case %s length %d and %d do not match", testCase.name, len(actualResult), len(testCase.expectedApplied))
		}
		for k, _ := range testCase.templates {
			actualAppliedTemplate, ok := actualResult[k]
			if !ok {
				t.Errorf("For test case %s, template key %s not found in result", testCase.name, string(k))
			}
			if actualAppliedTemplate != testCase.expectedApplied[k] {
				t.Errorf("For test case %s, applied template %s does not match expected result %s", testCase.name, actualAppliedTemplate, testCase.expectedApplied[k])
			}
		}
	}
}

// func TestModifyHeaders_SubstituteSecret(t *testing.T) {
// 	testCases := getDefaultTestCases(nil)
// 	secrets := getDefaultMockSecrets(nil)
// 	for _, testCase := range tests {
// 		for k, v := range testCase.Headers {
// 			templates[TemplateKey(k)] = Template(v)
// 		}
// 	}
// 	secrets := make(map[SecretKey]Secret)
// 	for k, v := range mockSecrets {
// 		secrets[SecretKey(k)] = Secret(v)
// 	}
// 	for i, test := range tests {
// 		keys := GetKeysFromTemplates(templates)
// 		appliedTemplates, _ := ApplyTemplates(templates, secrets)
// 		for header, _ := range test.Headers {
// 			actualHeaderVal, found := actualResult[header]
// 			expectedHeaderVal := test.Expected[header]
// 			if !found {
// 				t.Errorf("In test %d: Header %s not found", i, header)
// 			}
// 			if actualHeaderVal != expectedHeaderVal {
// 				t.Errorf("In test %d: Header value %s does not match %s for header %s", i, actualHeaderVal, expectedHeaderVal, header)
// 			}
// 		}
// 	}
// }
