package transform

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
)

// KeyMapping defines a single key mapping transformation
type KeyMapping struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`
}

// TransformMode defines how keys should be handled after transformation
type TransformMode string

const (
	// TransformModeKeepAll keeps all original keys plus transformed keys
	TransformModeKeepAll TransformMode = "keep_all"
	// TransformModeTransformedOnly keeps only the transformed keys
	TransformModeTransformedOnly TransformMode = "transformed_only"
)

// SecretTransform handles transformation of secret keys
type SecretTransform struct {
	mappings []KeyMapping
	mode     TransformMode
	logger   zerolog.Logger
}

// SecretTransformConfig defines the configuration structure for secret transformation
type SecretTransformConfig struct {
	KeyMappings []KeyMapping  `json:"key_mappings" yaml:"key_mappings"`
	Mode        TransformMode `json:"mode" yaml:"mode"`
}

// NewSecretTransform creates a new SecretTransform instance
func NewSecretTransform(mappings []KeyMapping, mode TransformMode, logger zerolog.Logger) *SecretTransform {
	if mappings == nil {
		mappings = make([]KeyMapping, 0)
	}
	if mode == "" {
		mode = TransformModeKeepAll // Default to keeping all keys
	}
	return &SecretTransform{
		mappings: mappings,
		mode:     mode,
		logger:   logger,
	}
}

// ParseSecretTransformFromConfig extracts secret transform configuration from config map
func ParseSecretTransformFromConfig(config map[string]interface{}, logger zerolog.Logger) (*SecretTransform, error) {
	var keyMappings []KeyMapping
	var mode TransformMode = TransformModeKeepAll

	secretTransformI, found := config["transform"]
	if !found {
		return NewSecretTransform(keyMappings, mode, logger), nil
	}

	secretTransformConfig, ok := secretTransformI.(map[string]interface{})
	if !ok {
		logger.Error().Msg("'transform' must be an object")
		return nil, fmt.Errorf("config not valid")
	}

	// Parse mode
	if modeI, hasMode := secretTransformConfig["mode"]; hasMode {
		modeStr, ok := modeI.(string)
		if !ok {
			logger.Error().Msg("transform.mode must be a string")
			return nil, fmt.Errorf("config not valid")
		}

		switch modeStr {
		case "keep_all":
			mode = TransformModeKeepAll
		case "transformed_only":
			mode = TransformModeTransformedOnly
		default:
			logger.Error().Msgf("invalid mode '%s', must be 'keep_all' or 'transformed_only'", modeStr)
			return nil, fmt.Errorf("config not valid")
		}
	}

	// Parse key mappings
	keyMappingsI, found := secretTransformConfig["key_mappings"]
	if !found {
		return NewSecretTransform(keyMappings, mode, logger), nil
	}

	keyMappingsList, ok := keyMappingsI.([]interface{})
	if !ok {
		logger.Error().Msg("'transform.key_mappings' must be a list")
		return nil, fmt.Errorf("config not valid")
	}

	for i, mappingI := range keyMappingsList {
		mappingMap, ok := mappingI.(map[string]interface{})
		if !ok {
			logger.Error().Msgf("transform.key_mappings[%d] must be an object", i)
			return nil, fmt.Errorf("config not valid")
		}

		fromI, hasFrom := mappingMap["from"]
		toI, hasTo := mappingMap["to"]

		if !hasFrom || !hasTo {
			logger.Error().Msgf("transform.key_mappings[%d] must have both 'from' and 'to' fields", i)
			return nil, fmt.Errorf("config not valid")
		}

		from, ok := fromI.(string)
		if !ok {
			logger.Error().Msgf("transform.key_mappings[%d].from must be a string", i)
			return nil, fmt.Errorf("config not valid")
		}

		to, ok := toI.(string)
		if !ok {
			logger.Error().Msgf("transform.key_mappings[%d].to must be a string", i)
			return nil, fmt.Errorf("config not valid")
		}

		keyMappings = append(keyMappings, KeyMapping{
			From: from,
			To:   to,
		})
	}

	return NewSecretTransform(keyMappings, mode, logger), nil
}

// Transform applies key mapping to the secret string
func (st *SecretTransform) Transform(secretString string) (string, error) {
	if len(st.mappings) == 0 {
		return secretString, nil
	}

	var secretData map[string]interface{}
	err := json.Unmarshal([]byte(secretString), &secretData)
	if err != nil {
		st.logger.Debug().Err(err).Msg("Failed to parse secret as JSON for transformation, returning original")
		return secretString, nil // Return original if not JSON
	}

	var mappedData map[string]interface{}

	switch st.mode {
	case TransformModeKeepAll:
		// Start with all original keys
		mappedData = make(map[string]interface{})
		for key, value := range secretData {
			mappedData[key] = value
		}
	case TransformModeTransformedOnly:
		// Start with empty map, only add transformed keys
		mappedData = make(map[string]interface{})
	}

	// Apply mappings
	for _, mapping := range st.mappings {
		found := false

		// Direct match
		if value, exists := secretData[mapping.From]; exists {
			mappedData[mapping.To] = value
			if st.mode == TransformModeKeepAll {
				delete(mappedData, mapping.From) // Remove original key in keep_all mode
			}
			st.logger.Debug().Msgf("Mapped key '%s' to '%s'", mapping.From, mapping.To)
			found = true
		} else {
			// Case-insensitive match
			for originalKey, value := range secretData {
				if strings.ToLower(originalKey) == strings.ToLower(mapping.From) {
					mappedData[mapping.To] = value
					if st.mode == TransformModeKeepAll {
						delete(mappedData, originalKey) // Remove original key in keep_all mode
					}
					st.logger.Debug().Msgf("Mapped key '%s' to '%s' (case-insensitive)", originalKey, mapping.To)
					found = true
					break
				}
			}
		}

		if !found {
			st.logger.Warn().Msgf("Key mapping: source key '%s' not found in secret", mapping.From)
		}
	}

	mappedBytes, err := json.Marshal(mappedData)
	if err != nil {
		st.logger.Err(err).Msg("Failed to marshal transformed secret data")
		return "", err
	}

	st.logger.Debug().
		Str("mode", string(st.mode)).
		Int("original_keys", len(secretData)).
		Int("transformed_keys", len(mappedData)).
		Msg("Applied secret transformation")

	return string(mappedBytes), nil
}

// HasTransformations returns true if the transformer has any key mappings configured
func (st *SecretTransform) HasTransformations() bool {
	return len(st.mappings) > 0
}

// GetMappings returns the list of key mappings
func (st *SecretTransform) GetMappings() []KeyMapping {
	return st.mappings
}

// GetMode returns the transformation mode
func (st *SecretTransform) GetMode() TransformMode {
	return st.mode
}
