package aws_sm_oauth

import (
	"time"

	"github.com/rs/zerolog"
)

func logConfig(awsSmOAuth AwsSmOAuth, tokenCacheTtl time.Duration,
	tokenCacheSize int, logger zerolog.Logger,
) {
	certificateCacheTtl := time.Duration(awsSmOAuth.awsSecretsManager.CacheConfig.CacheItemTTL) * time.Nanosecond
	logger.Info().
		Str("certificate_cache_ttl", certificateCacheTtl.String()).
		Str("certificate_secret_id", awsSmOAuth.certificateSecretId).
		Str("oauth_url", awsSmOAuth.oAuthUrl.String()).
		Str("oauth_client_id", awsSmOAuth.oAuthClientId).
		Str("token_cache_ttl", tokenCacheTtl.String()).
		Int("token_cache_size", tokenCacheSize).
		Str("jwt_duration", awsSmOAuth.jwtDuration.String()).
		Msg("Creating provider")
}