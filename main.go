package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/hasura/hasura-secret-refresh/provider"
	awsSm "github.com/hasura/hasura-secret-refresh/provider/aws_secrets_manager"
	awsSmOauth "github.com/hasura/hasura-secret-refresh/provider/aws_sm_oauth"
	"github.com/hasura/hasura-secret-refresh/server"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

const (
	ConfigFileCliFlag            = "config"
	ConfigFileDefaultPath        = "./config.json"
	ConfigFileCliFlagDescription = "path to config file"
)

const (
	aws_secrets_manager = "proxy_aws_secrets_manager"
	aws_sm_oauth        = "proxy_awssm_oauth"
	aws_sm_file         = "file_aws_secrets_manager"
)

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	configPath := viper.ConfigFileUsed()
	logLevel := viper.GetString("log_config.level")

	initLogger := logger.With().
		Str("config_file_path", configPath).
		Bool("is_default_path", isDefaultPath(configPath)).
		Logger()

	conf := viper.GetViper().AllSettings()

	config, fileProviders, err := parseConfig(conf, logger)
	if err != nil {
		initLogger.Fatal().Err(err).Msg("Unable to parse config file")
	}
	zLogLevel := getLogLevel(logLevel, logger)
	zerolog.SetGlobalLevel(zLogLevel)
	totalProviders := len(fileProviders) + len(config.Providers)
	logger.Info().Msgf("%d providers initialized: %d file provider, %d http provider",
		totalProviders, len(fileProviders), len(config.Providers),
	)
	for _, p := range fileProviders {
		go p.Start()
	}
	httpServer := server.Create(config, logger)
	http.Handle("/", httpServer)
	refreshEndpoint := viper.GetString("refresh_config.endpoint")
	if _, hasRefreshConfig := conf["refresh_config"]; hasRefreshConfig {
		refreshConfig := make(map[string]provider.FileProvider)
		for _, p := range fileProviders {
			refreshConfig[p.FileName()] = p
		}
		refresher := server.RefreshConfig{refreshConfig}
		http.Handle(refreshEndpoint, refresher)
	}
	err = http.ListenAndServe(":5353", nil)
	if err != nil {
		logger.Err(err).Msg("Error from server")
	}
}

func getLogLevel(level string, logger zerolog.Logger) zerolog.Level {
	levelMap := map[string]zerolog.Level{
		"debug": zerolog.DebugLevel,
		"info":  zerolog.InfoLevel,
		"error": zerolog.ErrorLevel,
	}
	zLevel, ok := levelMap[level]
	if !ok {
		logger.Info().Msg("Setting log level to 'info'")
		return zerolog.InfoLevel
	} else {
		logger.Info().Msgf("Setting log level to '%s'", level)
		return zLevel
	}
}

func parseConfig(rawConfig map[string]interface{}, logger zerolog.Logger) (config server.Config, fileProviders []provider.FileProvider, err error) {
	config.Providers = make(map[string]provider.HttpProvider)
	fileProviders = make([]provider.FileProvider, 0, 0)
	for k, v := range rawConfig {
		if k == "log_config" || k == "refresh_config" {
			continue
		}
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
		sublogger := logger.With().Str("provider_name", k).Str("provider_type", providerType).Logger()
		if providerType == aws_secrets_manager {
			var provider_ provider.HttpProvider
			provider_, err = awsSm.Create(providerData, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
			config.Providers[k] = provider_
		} else if providerType == aws_sm_oauth {
			var provider_ provider.HttpProvider
			provider_, err = awsSmOauth.Create(providerData, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
			config.Providers[k] = provider_
		} else if providerType == aws_sm_file {
			var fProvider_ provider.FileProvider
			fProvider_, err = awsSm.CreateAwsSecretsManagerFile(providerData, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
			fileProviders = append(fileProviders, fProvider_)
		} else {
			err = fmt.Errorf("Unknown provider type '%s' specified for provider '%s'", providerType, k)
			logger.Err(err).Msgf("Error in config")
			return
		}
	}
	return
}

func isDefaultPath(configPath string) bool {
	return configPath == ConfigFileDefaultPath
}
