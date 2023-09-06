package main

import (
	"flag"
	"os"

	"github.com/hasura/hasura-secret-refresh/server"
	"github.com/rs/zerolog"
)

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	configPath := flag.String(server.ConfigFileCliFlag, server.ConfigFileDefaultPath, server.ConfigFileCliFlagDescription)
	logLevel := flag.String("log", "info", "set log level: debug, info, error")
	flag.Parse()
	initLogger := logger.With().
		Str("config_file_path", *configPath).
		Bool("is_default_path", server.IsDefaultPath(configPath)).
		Logger()
	data, err := os.ReadFile(*configPath)
	if err != nil {
		initLogger.Fatal().Err(err).Msg("Unable to read config file")
	}
	config, err := server.ParseConfig(data, logger)
	if err != nil {
		initLogger.Fatal().Err(err).Msg("Unable to parse config file")
	}
	zLogLevel := getLogLevel(*logLevel, logger)
	zerolog.SetGlobalLevel(zLogLevel)
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
