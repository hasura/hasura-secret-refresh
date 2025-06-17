package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/hasura/hasura-secret-refresh/provider"
	awsIamRds "github.com/hasura/hasura-secret-refresh/provider/aws_iam_auth_rds"
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

type DeploymentType string

const (
	InitContainer DeploymentType = "initcontainer"
	Sidecar       DeploymentType = "sidecar"
)

const (
	aws_secrets_manager = "proxy_aws_secrets_manager"
	aws_sm_oauth        = "proxy_awssm_oauth"
	aws_sm_file         = "file_aws_secrets_manager"
	aws_iam_auth_rds    = "file_aws_iam_auth_rds"
)

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	// accept an environment variable for config path
	// and set the same as the config path
	if configPath := os.Getenv("CONFIG_PATH"); configPath != "" {
		viper.AddConfigPath(configPath)
	}

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

	config, fileProviders, deploymentType, err := parseConfig(conf, logger)
	if err != nil {
		initLogger.Fatal().Err(err).Msg("Unable to parse config file")
	}
	zLogLevel := getLogLevel(logLevel, logger)
	zerolog.SetGlobalLevel(zLogLevel)
	totalProviders := len(fileProviders) + len(config.Providers)
	logger.Info().Msgf("%d providers initialized: %d file provider, %d http provider",
		totalProviders, len(fileProviders), len(config.Providers),
	)

	// if the type is init container, then we need to identify the last execution status to mark
	// whether we are done with fileProvider or not?
	// init-container cannot be used to detect loading of proxy based secret
	// retriever
	if deploymentType == InitContainer {
		// Just run the refresh method and if anything fails, exit
		for _, p := range fileProviders {
			err := p.Refresh()
			if err != nil {
				// os.Exit() or something
				logger.Err(err).Msg("Encountered an error while loading secrets from configured file providers")
				os.Exit(1)
			}
		}
		logger.Info().Msg("Loaded all secrets into file")
		os.Exit(0)
		// Exit gracefully
	}

	for _, p := range fileProviders {
		go p.Start()
	}
	httpServer := server.Create(config, logger)
	http.Handle("/", httpServer)

	// add a healthcheck
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	refreshEndpoint := viper.GetString("refresh_config.endpoint")
	if _, hasRefreshConfig := conf["refresh_config"]; hasRefreshConfig {
		refreshConfig := make(map[string]provider.FileProvider)
		for _, p := range fileProviders {
			refreshConfig[p.FileName()] = p
		}
		refresher := server.RefreshConfig{refreshConfig, logger}
		http.Handle(refreshEndpoint, refresher)
		logger.Info().Msgf("Refresh endpoint set to: %s", refreshEndpoint)
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

func parseConfig(rawConfig map[string]interface{}, logger zerolog.Logger) (config server.Config, fileProviders []provider.FileProvider, deploymentType DeploymentType, err error) {
	config.Providers = make(map[string]provider.HttpProvider)
	fileProviders = make([]provider.FileProvider, 0, 0)
	for k, v := range rawConfig {
		if k == "type" {
			t := v.(string)
			switch t {
			case "initcontainer":
				deploymentType = InitContainer
			default:
				deploymentType = Sidecar
			}
			continue
		}
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
		} else if providerType == aws_iam_auth_rds {
			var iamProvider provider.FileProvider
			iamProvider, err = awsIamRds.New(providerData, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
			fileProviders = append(fileProviders, iamProvider)
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
