package process_secrets

import (
	"regexp"
)

var regex = regexp.MustCompile("##(.*?)##")

func GetChangedHeaders(
	current map[string]string, secretsStore SecretsStore) (new map[string]string, err error,
) {
	secretsToFetch := getSecretsInHeaders(current)
	secrets, err := secretsStore.FetchSecrets(secretsToFetch)
	if err != nil {
		return
	}
	new, err = replaceSecretTemplate(current, secrets)
	if err != nil {
		//TODO: Handle error
	}
	return
}

func getSecretsInHeaders(current map[string]string) []string {
	secretsToFetch := make(map[string]bool)
	for _, headerVal := range current {
		matches := regex.FindAllStringSubmatch(headerVal, -1)
		for _, v := range matches {
			secretKey := v[1]
			secretsToFetch[secretKey] = true
		}
	}
	secretsToFetchList := make([]string, 0, len(secretsToFetch))
	for k, _ := range secretsToFetch {
		secretsToFetchList = append(secretsToFetchList, k)
	}
	return secretsToFetchList
}

func replaceSecretTemplate(current map[string]string, secrets map[string]string,
) (newHeaders map[string]string, err error) {
	newHeaders = make(map[string]string)
	for header, headerVal := range current {
		newHeaderVal := regex.ReplaceAllStringFunc(headerVal, func(s string) string {
			matches := regex.FindStringSubmatch(s)
			secretKey := matches[1]
			secret, ok := secrets[secretKey]
			if !ok {
				//TODO: Handle error
			}
			return secret
		})
		newHeaders[header] = newHeaderVal
	}
	return
}
