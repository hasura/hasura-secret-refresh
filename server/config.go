package server

import (
	"time"

	"github.com/hasura/hasura-secret-refresh/provider"
)

const (
	ConfigFileCliFlag            = "config"
	ConfigFileDefaultPath        = "./config.json"
	ConfigFileCliFlagDescription = "path to config file"
)

type Config struct {
	Providers map[string]provider.Provider
}

func ParseConfig(rawConfig []byte) (Config, error) {
	//TODO: Implement configuration
	awsSmProvider, _ := provider.CreateAwsSecretsManagerProvider(time.Minute * 5)
	return Config{Providers: map[string]provider.Provider{
		"aws_secret_manager": awsSmProvider,
	}}, nil
}
