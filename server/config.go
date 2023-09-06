package server

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
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
	TokenCacheTtl       int64  `toml:"token_cache_ttl"`
	TokenCacheSize      int    `toml:"token_cache_size"`
	CertificateCacheTtl int64  `toml:"certificate_cache_ttl"`
	CertificateSecretId string `toml:"certificate_secret_id"`
	OauthUrl            string `toml:"oauth_url"`
	OauthClientId       string `toml:"oauth_client_id"`
	JwtClaimMap         string `toml:"jwt_claims_map"`
	JwtDuration         int64  `toml:"jwt_duration"`
}

const (
	aws_secrets_manager = "aws_secrets_manager"
	aws_sm_oauth        = "awssm_oauth"
)

func ParseConfig(rawConfig []byte, logger zerolog.Logger) (config Config, err error) {
	parsedConfig := make(map[string]ProviderConfig)
	config.Providers = make(map[string]provider.Provider)
	_, err = toml.Decode(string(rawConfig), &parsedConfig)
	if err != nil {
		return
	}
	for k, v := range parsedConfig {
		var provider_ provider.Provider
		if k == aws_secrets_manager {
			sublogger := logger.With().Str("provider_name", aws_secrets_manager).Logger()
			provider_, err = getAwsSecretsManagerProvider(v, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
		} else if k == aws_sm_oauth {
			sublogger := logger.With().Str("provider_name", aws_sm_oauth).Logger()
			provider_, err = getAwsSmOAuthProvider(v, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
		}
		config.Providers[k] = provider_
	}
	return
}

func getAwsSecretsManagerProvider(config ProviderConfig, logger zerolog.Logger) (provider_ provider.AwsSecretsManager, err error) {
	provider_, err = provider.CreateAwsSecretsManagerProvider(
		time.Duration(config.TokenCacheTtl)*time.Second,
		logger,
	)
	return
}

func getAwsSmOAuthProvider(config ProviderConfig, logger zerolog.Logger) (provider_ provider.AwsSmOAuth, err error) {
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
		time.Duration(config.CertificateCacheTtl)*time.Second,
		config.CertificateSecretId,
		*oAuthParsedUrl,
		config.OauthClientId,
		claims,
		time.Duration(config.TokenCacheTtl)*time.Second,
		config.TokenCacheSize,
		time.Duration(config.JwtDuration)*time.Second,
		logger,
	)
	return
}
