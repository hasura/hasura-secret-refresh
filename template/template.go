package template

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type Template string

var regex = regexp.MustCompile("##(.*?)##")

func (t Template) Substitute(with string) string {
	result := regex.ReplaceAllStringFunc(string(t), func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimLeft(s, "##")
		s = strings.TrimRight(s, "##")
		res := jsonTemplate(s, with)
		return res
	})
	return result
}

func jsonTemplate(jsonTemplate, substituteWith string) string {
	jsonPath := strings.Split(jsonTemplate, ".")
	if len(jsonPath) < 2 {
		return substituteWith
	}
	jsonParsed := make(map[string]interface{})
	err := json.Unmarshal([]byte(substituteWith), &jsonParsed)
	if err != nil {
		return ""
	}
	jsonKey := strings.TrimSpace(jsonPath[1])
	val, ok := jsonParsed[jsonKey]
	if !ok {
		return ""
	}
	valS := fmt.Sprintf("%v", val)
	val = strings.TrimSpace(valS)
	return valS
}
