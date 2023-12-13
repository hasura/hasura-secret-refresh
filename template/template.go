package template

import (
	"encoding/json"
	"fmt"
	"reflect"
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
	result := regex.ReplaceAllStringFunc(string(t.Templ), func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimLeft(s, "##")
		s = strings.TrimRight(s, "##")
		res := jsonTemplate(s, with, t.Logger)
		return res
	})
	return result
}

func jsonTemplate(jsonTemplate, substituteWith string, logger zerolog.Logger) string {
	jsonPath := strings.Split(jsonTemplate, ".")
	if len(jsonPath) < 2 {
		return substituteWith
	}
	jsonParsed := make(map[string]interface{})
	err := json.Unmarshal([]byte(substituteWith), &jsonParsed)
	if err != nil {
		logger.Err(err).Msg("Unable to parse secret as a JSON")
		logger.Debug().Err(err).Msgf("Unable to parse secret as a JSON: %s", substituteWith)
		return ""
	}
	jsonKey := strings.TrimSpace(jsonPath[1])
	val, ok := jsonParsed[jsonKey]
	if !ok {
		logger.Error().Msgf("Key %s not found in secret", jsonKey)
		logger.Debug().Msgf("Key %s not found in secret %s", jsonKey, substituteWith)
		return ""
	}
	if reflect.ValueOf(val).Kind() == reflect.Map {
		logger.Error().Msgf("Nested JSON is not supported in secrets")
		logger.Debug().Msgf("Nested JSON is not supported, secret: %s", substituteWith)
		return ""
	}
	valS := fmt.Sprintf("%v", val)
	valS = strings.TrimSpace(valS)
	return valS
}
