package main

import (
	"github.com/hasura/hasura-secret-refresh/provider"
	awsSm "github.com/hasura/hasura-secret-refresh/provider/aws_secrets_manager"
	awsSmOauth "github.com/hasura/hasura-secret-refresh/provider/aws_sm_oauth"
	"github.com/hasura/hasura-secret-refresh/server"

	"github.com/rs/zerolog"
)

const (
	ConfigFileCliFlag            = "config"
	ConfigFileDefaultPath        = "./config.json"
	ConfigFileCliFlagDescription = "path to config file"
)

const (
	aws_secrets_manager = "aws_secrets_manager"
	aws_sm_oauth        = "awssm_oauth"
	aws_sm_file         = "aws_secrets_manager_file"
)

func ParseConfig(rawConfig map[string]interface{}, logger zerolog.Logger) (config server.Config, fileProviders []provider.FileProvider, err error) {
	config.Providers = make(map[string]provider.HttpProvider)
	fileProviders = make([]provider.FileProvider, 0, 0)
	for k, v := range rawConfig {
		if k == "log_config" {
			continue
		}
		var provider_ provider.HttpProvider
		var fProvider_ provider.FileProvider
		providerData, ok := v.(map[string]interface{})
		if !ok {
			logger.Error().Msgf("Failed to convert config to required type")
			return
		}
		providerTypeI, found := providerData["type"]
		if !found {
			logger.Error().Msgf("Provider type not specified for %s. Ensure that the type is specified for every provider using the 'type' field", k)
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
		} else if providerType == aws_sm_file {
			sublogger := logger.With().Str("provider_name", aws_sm_file).Logger()
			fProvider_, err = awsSm.CreateAwsSecretsManagerFile(providerData, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
			fileProviders = append(fileProviders, fProvider_)
		}
		config.Providers[k] = provider_
	}
	return
}

func IsDefaultPath(configPath string) bool {
	return configPath == ConfigFileDefaultPath
}
