package server

import (
	"encoding/json"
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
	SecretsManagerCacheTtl int64  `toml:"certificate_cache_ttl"`
	CertificateSecretId    string `toml:"certificate_secret_id"`
	OauthUrl               string `toml:"oauth_url"`
	OauthClientId          string `toml:"oauth_client_id"`
	JwtClaimMap            string `toml:"jwt_claims_map"`
	JwtExpiration          int64  `toml:"jwt_expiration"`
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
		if k == "aws_secrets_manager" {
			provider_, err = getAwsSecretsManagerProvider(v)
			if err != nil {
				return
			}
		} else if k == "awssm_oauth" {
			provider_, err = getAwsSmOAuthProvider(v)
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

func getAwsSmOAuthProvider(config ProviderConfig) (provider_ provider.AwsSmOAuth, err error) {
	oAuthParsedUrl, err := url.Parse(config.OauthUrl)
	if err != nil {
		return
	}
	claims := make(map[string]interface{})
	err = json.Unmarshal([]byte(config.JwtClaimMap), &claims)
	if err != nil {
		return
	}
	provider_, err = provider.CreateAwsSmOAuthProvider(
		time.Duration(config.SecretsManagerCacheTtl)*time.Second,
		config.CertificateSecretId,
		*oAuthParsedUrl,
		config.OauthClientId,
		claims,
	)
	return
}
