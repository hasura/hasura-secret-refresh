package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var regex = regexp.MustCompile("##(.*?)##")

func getHeaderFromTemplate(
	headerTemplate string, substituteWith string,
) (
	headerKey string, headerVal string, err error,
) {
	split := strings.Split(headerTemplate, ":")
	if len(split) != 2 {
		return headerKey, headerVal, errors.New(fmt.Sprintf("Header template %s is not valid", headerTemplate))
	}
	headerKey = split[0]
	headerKey = strings.TrimSpace(headerKey)
	headerValTemplate := split[1]
	headerValTemplate = strings.TrimSpace(headerValTemplate)
	headerVal = regex.ReplaceAllStringFunc(headerValTemplate, func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimLeft(s, "##")
		s = strings.TrimRight(s, "##")
		res := jsonTemplate(s, substituteWith)
		return res
	})
	return
}

func jsonTemplate(jsonTemplate, substituteWith string) string {
	jsonPath := strings.Split(jsonTemplate, ".")
	if len(jsonPath) < 2 {
		return substituteWith
	}
	jsonParsed := make(map[string]string)
	err := json.Unmarshal([]byte(substituteWith), &jsonParsed)
	if err != nil {
		return ""
	}
	jsonKey := strings.TrimSpace(jsonPath[1])
	val, ok := jsonParsed[jsonKey]
	if !ok {
		return ""
	}
	val = strings.TrimSpace(val)
	return val
}
