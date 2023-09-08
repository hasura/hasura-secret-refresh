package server

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var regex = regexp.MustCompile("##(.*?)##")

func GetHeaderFromTemplate(
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
		return substituteWith
	})
	return
}
