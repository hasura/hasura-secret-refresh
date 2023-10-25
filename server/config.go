package server

import (
	"github.com/hasura/hasura-secret-refresh/provider"
	awsSm "github.com/hasura/hasura-secret-refresh/provider/aws_secrets_manager"
	awsSmOauth "github.com/hasura/hasura-secret-refresh/provider/aws_sm_oauth"

	"github.com/rs/zerolog"
)

const (
	ConfigFileCliFlag            = "config"
	ConfigFileDefaultPath        = "./config.json"
	ConfigFileCliFlagDescription = "path to config file"
)

type Config struct {
	Providers map[string]provider.HttpProvider
}

const (
	aws_secrets_manager = "aws_secrets_manager"
	aws_sm_oauth        = "awssm_oauth"
)

func ParseConfig(rawConfig map[string]interface{}, logger zerolog.Logger) (config Config, err error) {
	config.Providers = make(map[string]provider.HttpProvider)
	for k, v := range rawConfig {
		var provider_ provider.HttpProvider
		providerData, ok := v.(map[string]interface{})
		if !ok {
			logger.Error().Msgf("Failed to convert config to required type")
			return
		}
		providerTypeI, found := providerData["type"]
		if !found {
			logger.Error().Msgf("Provider type not specified. Ensure that the type is specified for every provider using the 'type' field")
			return
		}
		providerType, ok := providerTypeI.(string)
		if !ok {
			logger.Error().Msgf("'type' of provider must be a string value")
			return
		}
		if providerType == aws_secrets_manager {
			sublogger := logger.With().Str("provider_name", aws_secrets_manager).Logger()
			provider_, err = awsSm.Create(providerData, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
		} else if providerType == aws_sm_oauth {
			sublogger := logger.With().Str("provider_name", aws_sm_oauth).Logger()
			provider_, err = awsSmOauth.Create(providerData, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
		}
		config.Providers[k] = provider_
	}
	return
}
