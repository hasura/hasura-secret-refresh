package process_secrets

import "regexp"

func GetChangedHeaders(
	current map[string]string, secretsStore SecretsStore) (new map[string]string, err error,
) {
	new = make(map[string]string)
	regex := regexp.MustCompile("##(.*?)##")
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
	secrets, err := secretsStore.FetchSecrets(secretsToFetchList)
	if err != nil {
		return
	}
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
		new[header] = newHeaderVal
	}
	return
}
