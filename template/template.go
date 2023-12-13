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

func jsonTemplate(jsonTemplate, substituteWith string, logger zerolog.Logger) (res string, canContinue bool) {
	jsonPath := strings.Split(jsonTemplate, ".")
	if len(jsonPath) < 2 {
		return substituteWith, true
	}
	jsonParsed := make(map[string]interface{})
	err := json.Unmarshal([]byte(substituteWith), &jsonParsed)
	if err != nil {
		logger.Err(err).Msg("Unable to parse secret as a JSON")
		logger.Debug().Err(err).Msgf("Unable to parse secret as a JSON: %s", substituteWith)
		return "", false
	}
	jsonKey := strings.TrimSpace(jsonPath[1])
	val, ok := jsonParsed[jsonKey]
	if !ok {
		logger.Error().Msgf("Key %s not found in secret", jsonKey)
		logger.Debug().Msgf("Key %s not found in secret %s", jsonKey, substituteWith)
		return "", true
	}
	if reflect.ValueOf(val).Kind() == reflect.Map {
		logger.Error().Msgf("Nested JSON is not supported in secrets")
		logger.Debug().Msgf("Nested JSON is not supported, secret: %s", substituteWith)
		return "", true
	}
	valS := fmt.Sprintf("%v", val)
	valS = strings.TrimSpace(valS)
	return valS, true
}
