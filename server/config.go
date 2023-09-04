package server

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/BurntSushi/toml"
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

// a union of all config fields required by each provider
type ProviderConfig struct {
	CacheTtl               int64  `toml:"cache_ttl"`
	SecretsManagerCacheTtl int64  `toml:"secrets_manager_cache_ttl"`
	CertificateSecretId    string `toml:"certificate_secret_id"`
	OauthUrl               string `toml:"oauth_url"`
	OauthClientId          string `toml:"oauth_client_id"`
	JwtClaimMap            string `toml:"jwt_claims_map"`
}

func ParseConfig(rawConfig []byte) (config Config, err error) {
	parsedConfig := make(map[string]ProviderConfig)
	config.Providers = make(map[string]provider.Provider)
	_, err = toml.Decode(string(rawConfig), &parsedConfig)
	if err != nil {
		return
	}
	for k, v := range parsedConfig {
		var provider_ provider.Provider
		if k == "aws_secret_manager" {
			provider_, err = getAwsSecretsManagerProvider(v)
			if err != nil {
				return
			}
		} else if k == "idanywhere" {
			provider_, err = getIdAnywhereProvider(v)
			if err != nil {
				return
			}
		}
		config.Providers[k] = provider_
	}
	return
}

func getAwsSecretsManagerProvider(config ProviderConfig) (provider_ provider.AwsSecretsManager, err error) {
	provider_, err = provider.CreateAwsSecretsManagerProvider(time.Duration(config.CacheTtl) * time.Second)
	return
}

func getIdAnywhereProvider(config ProviderConfig) (provider_ provider.IdAnywhere, err error) {
	oAuthParsedUrl, err := url.Parse(config.OauthUrl)
	if err != nil {
		return
	}
	claims := make(map[string]string)
	err = json.Unmarshal([]byte(config.JwtClaimMap), &claims)
	if err != nil {
		fmt.Printf("%v", config.JwtClaimMap == "")
		fmt.Printf(">>>>> %+v", config.JwtClaimMap)
		return
	}
	provider_, err = provider.CreateIdAnywhereProvider(
		time.Duration(config.SecretsManagerCacheTtl)*time.Second,
		config.CertificateSecretId,
		*oAuthParsedUrl,
		config.OauthClientId,
		claims,
	)
	return
}
