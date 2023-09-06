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
	flag.Parse()
	logger = logger.With().
		Str("config_file_path", *configPath).
		Bool("is_default_path", server.IsDefaultPath(configPath)).
		Logger()
	data, err := os.ReadFile(*configPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("Unable to read config file")
	}
	config, err := server.ParseConfig(data)
	if err != nil {
		logger.Fatal().Err(err).Msg("Unable to parse config file")
	}
	server.Serve(config)
}
