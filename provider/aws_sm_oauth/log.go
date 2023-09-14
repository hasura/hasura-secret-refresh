package aws_sm_oauth

import (
	"fmt"
	"time"

	"github.com/rs/zerolog"
)

func logConfig(awsSmOAuth AwsSmOAuth, tokenCacheTtl time.Duration,
	tokenCacheSize int, logger zerolog.Logger,
) {
	certificateCacheTtl := time.Duration(awsSmOAuth.awsSecretsManager.CacheConfig.CacheItemTTL) * time.Nanosecond
	logger.Info().
		Str("certificate_cache_ttl", certificateCacheTtl.String()).
		Str("certificate_region", awsSmOAuth.certificateRegion).
		Str("oauth_url", awsSmOAuth.oAuthUrl.String()).
		Str("token_cache_ttl", tokenCacheTtl.String()).
		Int("token_cache_size", tokenCacheSize).
		Str("jwt_duration", awsSmOAuth.jwtDuration.String()).
		Dict("retry_config", zerolog.Dict().
			Str("max_attempts", fmt.Sprint(awsSmOAuth.httpClient.RetryMax)).
			Str("min_wait", awsSmOAuth.httpClient.RetryWaitMin.String()).
			Str("max_wait", awsSmOAuth.httpClient.RetryWaitMax.String())).
		Msg("Creating provider")
}
