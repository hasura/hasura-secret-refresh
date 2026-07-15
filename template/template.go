package template

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
)

type Template struct {
	Templ  string
	Logger zerolog.Logger
}

var regex = regexp.MustCompile("##(.*?)##")

func (t Template) Substitute(with string) string {
	canContinue := true
	result := regex.ReplaceAllStringFunc(string(t.Templ), func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimLeft(s, "##")
		s = strings.TrimRight(s, "##")
		var res string
		if canContinue {
			res, canContinue = jsonTemplate(s, with, t.Logger)
		}
		return res
	})
	return result
}

func jsonTemplate(templateKey, substituteWith string, logger zerolog.Logger) (res string, canContinue bool) {
	jsonPath := strings.Split(templateKey, ".")
	if len(jsonPath) < 2 {
		return substituteWith, true
	}
	jsonParsed := make(map[string]interface{})
	err := json.Unmarshal([]byte(substituteWith), &jsonParsed)
	if err != nil {
		logJSONTemplateParseError(logger, templateKey, substituteWith, err)
		return "", false
	}
	jsonKey := strings.TrimSpace(jsonPath[1])
	val, ok := jsonParsed[jsonKey]
	if !ok {
		logger.Error().
			Str("template_key", templateKey).
			Msg("Template key not found in secret JSON")
		return "", true
	}
	if _, isMap := val.(map[string]interface{}); isMap {
		logger.Error().
			Str("template_key", templateKey).
			Msg("Nested JSON lookups are not supported in secrets")
		return "", true
	}
	valS := fmt.Sprintf("%v", val)
	valS = strings.TrimSpace(valS)
	return valS, true
}

func logJSONTemplateParseError(logger zerolog.Logger, templateKey, rawSecret string, err error) {
	event := logger.Error().
		Err(err).
		Str("template_key", templateKey)

	if offset, line, column, ok := jsonErrorPosition(rawSecret, err); ok {
		event = event.Int64("offset", offset).Int("line", line).Int("column", column)
	}

	event.Msg("Unable to parse secret as JSON for template lookup")
}

func jsonErrorPosition(rawSecret string, err error) (offset int64, line int, column int, ok bool) {
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		line, column = offsetToLineColumn(rawSecret, syntaxErr.Offset)
		return syntaxErr.Offset, line, column, true
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		line, column = offsetToLineColumn(rawSecret, typeErr.Offset)
		return typeErr.Offset, line, column, true
	}

	return 0, 0, 0, false
}

func offsetToLineColumn(rawSecret string, offset int64) (line int, column int) {
	if offset < 1 {
		return 1, 1
	}

	line = 1
	column = 1
	bytes := []byte(rawSecret)
	limit := int(offset - 1)
	if limit > len(bytes) {
		limit = len(bytes)
	}

	for i := 0; i < limit; i++ {
		if bytes[i] == '\n' {
			line++
			column = 1
			continue
		}
		column++
	}

	return line, column
}
