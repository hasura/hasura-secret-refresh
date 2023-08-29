package process_secrets

import (
	"regexp"
)

var regex = regexp.MustCompile("##(.*?)##")

type TemplateKey string
type Template string
type SecretKey string
type Secret string

func GetUniqueKeysFromTemplates(templates map[TemplateKey]Template) (keys []SecretKey) {
	uniqueKeys := make(map[SecretKey]bool)
	for _, template := range templates {
		keys := GetUniqueKeysFromTemplate(template)
		for _, i := range keys {
			uniqueKeys[i] = true
		}
	}
	for k, _ := range uniqueKeys {
		keys = append(keys, SecretKey(k))
	}
	return
}

func GetUniqueKeysFromTemplate(template Template) (keys []SecretKey) {
	uniqueKeys := make(map[string]bool)
	matches := regex.FindAllStringSubmatch(string(template), -1)
	for _, v := range matches {
		key := v[1]
		uniqueKeys[key] = true
	}
	for k, _ := range uniqueKeys {
		keys = append(keys, SecretKey(k))
	}
	return
}

func ApplyTemplates(templates map[TemplateKey]Template, secrets map[SecretKey]Secret) (
	appliedTemplates map[TemplateKey]string,
) {
	appliedTemplates = make(map[TemplateKey]string)
	for k, v := range templates {
		appliedTemplate := regex.ReplaceAllStringFunc(string(v), func(s string) string {
			matches := regex.FindStringSubmatch(s)
			key := matches[1]
			secret, _ := secrets[SecretKey(key)]

			return string(secret)
		})
		appliedTemplates[k] = appliedTemplate
	}
	return
}
