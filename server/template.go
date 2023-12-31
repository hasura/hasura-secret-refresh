package server

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hasura/hasura-secret-refresh/template"
	"github.com/rs/zerolog"
)

var regex = regexp.MustCompile("##(.*?)##")

func getHeaderFromTemplate(
	headerTemplate string, substituteWith string, logger zerolog.Logger,
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
	templ := template.Template{Templ: headerValTemplate, Logger: logger}
	headerVal = templ.Substitute(substituteWith)
	return
}
