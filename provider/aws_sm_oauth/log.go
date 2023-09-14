package aws_sm_oauth

import (
	"fmt"
	"net/http"
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

func logOauthRequest(request *http.Request, msg string, logger zerolog.Logger) {

	headerDict := zerolog.Dict()
	for k, _ := range request.Header {
		headerDict = headerDict.Str(k, request.Header.Get(k))
	}
	formDict := zerolog.Dict()
	for k, _ := range request.Form {
		formDict = formDict.Str(k, request.Form.Get(k))
	}
	logger.Debug().
		Str("host", request.Host).
		Str("method", request.Method).
		Str("url", request.URL.String()).
		Str("log_type", "request_log").
		Str("url", request.URL.String()).
		Str("method", request.Method).
		Dict("headers", headerDict).
		Dict("form", formDict).
		Msg(msg)
}

func logOAuthResponse(response *http.Response, msg string, logger zerolog.Logger) {
	headerDict := zerolog.Dict()
	for k, _ := range response.Header {
		headerDict = headerDict.Str(k, response.Header.Get(k))
	}
	logger.Debug().
		Str("status", response.Status).
		Str("log_type", "response_log").
		Dict("headers", headerDict).
		Msg(msg)
}
