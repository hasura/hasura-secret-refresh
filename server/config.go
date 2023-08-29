package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	ConfigFileCliFlag            = "config"
	ConfigFileDefaultPath        = "./config.json"
	ConfigFileCliFlagDescription = "path to config file"
)

type SecretsStoreType string

const (
	AwsSecretsStoreType = SecretsStoreType("aws_secrets_manager")
)

type Config struct {
	Providers []interface{}
}

type ConfigJson struct {
	Providers []ProviderJson `json:"providers"`
}

type ProviderJson struct {
	Type     string `json:"type"`
	CacheTtl int64  `json:"cache_ttl"`
}

type AwsSecretStoreConfig struct {
	ProviderType SecretsStoreType
	CacheTtl     time.Duration
}

func ParseConfig(raw []byte) (config Config, err error) {
	configJson := ConfigJson{}
	err = json.Unmarshal(raw, &configJson)
	if err != nil {
		return
	}
	for _, provider := range configJson.Providers {
		if provider.Type == string(AwsSecretsStoreType) {
			awsConfig, err := parseAwsSecretsConfig(provider)
			if err != nil {
				return config, err
			}
			config.Providers = append(config.Providers, awsConfig)
		} else {
			return config, errors.New(fmt.Sprintf("Unknown provider %s", provider.Type))
		}
	}
	return
}

func parseAwsSecretsConfig(providerConfig ProviderJson) (awsConfig AwsSecretStoreConfig, err error) {
	cacheTtl := providerConfig.CacheTtl
	return AwsSecretStoreConfig{
		ProviderType: AwsSecretsStoreType,
		CacheTtl:     time.Duration(cacheTtl) * time.Second,
	}, nil
}
