package aws_sm_oauth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"
)

func logConfig(config AwsSmOauth, tokenCacheTtl time.Duration,
	tokenCacheSize int, logger zerolog.Logger,
) {
	certificateCacheTtl := time.Duration(config.awsSecretsManager.CacheConfig.CacheItemTTL) * time.Nanosecond
	logger.Info().
		Str("certificate_cache_ttl", certificateCacheTtl.String()).
		Str("certificate_region", config.certificateRegion).
		Str("oauth_url", config.oAuthUrl.String()).
		Str("token_cache_ttl", tokenCacheTtl.String()).
		Int("token_cache_size", tokenCacheSize).
		Str("jwt_duration", config.jwtDuration.String()).
		Dict("retry_config", zerolog.Dict().
			Str("max_attempts", fmt.Sprint(config.httpClient.RetryMax)).
			Str("min_wait", config.httpClient.RetryWaitMin.String()).
			Str("max_wait", config.httpClient.RetryWaitMax.String())).
		Msg("Creating provider")
}

func logOauthRequest(url url.URL, method string, formData url.Values, header http.Header, msg string, logger zerolog.Logger) {
	headerDict := zerolog.Dict()
	for k, _ := range header {
		headerDict = headerDict.Str(k, header.Get(k))
	}
	formDict := zerolog.Dict()
	for k, _ := range formData {
		formDict = formDict.Str(k, formData.Get(k))
	}
	logger.Debug().
		Str("url", url.String()).
		Str("method", method).
		Str("log_type", "request_log").
		Dict("headers", headerDict).
		Dict("form", formDict).
		Msg(msg)
}

func logOAuthResponse(response *http.Response, msg string, logger zerolog.Logger) {
	debugLog := logger.Debug().
		Str("status", response.Status).
		Str("log_type", "response_log")
	if response.StatusCode != 200 {
		httpBodyByte, err := io.ReadAll(response.Body)
		if err == nil {
			httpBody := string(httpBodyByte)
			debugLog = debugLog.Str("body", httpBody)
		} else {
			debugLog = debugLog.Err(err)
		}
	}
	headerDict := zerolog.Dict()
	for k, _ := range response.Header {
		headerDict = headerDict.Str(k, response.Header.Get(k))
	}
	debugLog = debugLog.Dict("headers", headerDict)
	debugLog.Msg(msg)
}
