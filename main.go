package main

import (
	"fmt"
	"os"

	"github.com/hasura/hasura-secret-refresh/config"
	"github.com/hasura/hasura-secret-refresh/server"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
		return
	}

	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	configPath := viper.ConfigFileUsed()
	logLevel := viper.GetString("log_config.level")

	initLogger := logger.With().
		Str("config_file_path", configPath).
		Bool("is_default_path", config.IsDefaultPath(configPath)).
		Logger()

	conf := viper.GetViper().AllSettings()

	config, fileProviders, err := config.ParseConfig(conf, logger)
	if err != nil {
		initLogger.Fatal().Err(err).Msg("Unable to parse config file")
	}
	zLogLevel := getLogLevel(logLevel, logger)
	zerolog.SetGlobalLevel(zLogLevel)
	logger.Info().Msgf("%d file providers initialized", len(fileProviders))
	for _, p := range fileProviders {
		go p.Start()
	}
	server.Serve(config, logger)
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
