package server

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/hasura/hasura-secret-refresh/provider"
	awssm "github.com/hasura/hasura-secret-refresh/provider/aws_secrets_manager"
	awssmOauth "github.com/hasura/hasura-secret-refresh/provider/aws_sm_oauth"

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
	TokenCacheTtl       int64  `json:"token_cache_ttl"`
	TokenCacheSize      int    `json:"token_cache_size"`
	CertificateCacheTtl int64  `json:"certificate_cache_ttl"`
	OauthUrl            string `json:"oauth_url"`
	JwtClaimMap         string `json:"jwt_claims_map"`
	JwtDuration         int64  `json:"jwt_duration"`
	HttpMaxRetries      int    `json:"http_retry_attempts"`
	HttpRetryMinWait    int64  `json:"http_retry_min_wait"`
	HttpRetryMaxWait    int64  `json:"http_retry_max_wait"`
}

const (
	aws_secrets_manager = "aws_secrets_manager"
	aws_sm_oauth        = "awssm_oauth"
)

func ParseConfig(rawConfig map[string]interface{}, logger zerolog.Logger) (config Config, err error) {
	config.Providers = make(map[string]provider.Provider)
	for k, v := range rawConfig {
		var provider_ provider.Provider
		var providerData ProviderConfig

		marhalledValues, _ := json.Marshal(v)
		_ = json.Unmarshal(marhalledValues, &providerData)

		if k == aws_secrets_manager {
			sublogger := logger.With().Str("provider_name", aws_secrets_manager).Logger()
			provider_, err = getAwsSecretsManagerProvider(providerData, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
		} else if k == aws_sm_oauth {
			sublogger := logger.With().Str("provider_name", aws_sm_oauth).Logger()
			provider_, err = getAwsSmOAuthProvider(providerData, sublogger)
			if err != nil {
				sublogger.Err(err).Msgf("Error creating provider")
				return
			}
		}
		config.Providers[k] = provider_
	}
	return
}

func getAwsSecretsManagerProvider(config ProviderConfig, logger zerolog.Logger) (provider_ awssm.AwsSecretsManager, err error) {
	provider_, err = awssm.CreateAwsSecretsManagerProvider(
		time.Duration(config.TokenCacheTtl)*time.Second,
		logger,
	)
	return
}

func getAwsSmOAuthProvider(config ProviderConfig, logger zerolog.Logger) (provider_ awssmOauth.AwsSmOAuth, err error) {
	oAuthParsedUrl, err := url.Parse(config.OauthUrl)
	if err != nil {
		return
	}
	claims := make(map[string]interface{})
	err = json.Unmarshal([]byte(config.JwtClaimMap), &claims)
	if err != nil {
		return
	}
	provider_, err = awssmOauth.CreateAwsSmOAuthProvider(
		time.Duration(config.CertificateCacheTtl)*time.Second,
		*oAuthParsedUrl,
		claims,
		time.Duration(config.TokenCacheTtl)*time.Second,
		config.TokenCacheSize,
		time.Duration(config.JwtDuration)*time.Second,
		time.Duration(config.HttpRetryMinWait)*time.Second,
		time.Duration(config.HttpRetryMaxWait)*time.Second,
		config.HttpMaxRetries,
		logger,
	)
	return
}
