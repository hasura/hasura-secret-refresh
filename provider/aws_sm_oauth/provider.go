package aws_sm_oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

type AwsSmOauth struct {
	cache             *expirable.LRU[string, string]
	certificateRegion string
	awsSecretsManager *secretcache.Cache
	oAuthUrl          url.URL
	jwtClaimMap       map[string]interface{}
	jwtDuration       time.Duration
	httpClient        *retryablehttp.Client
	logger            zerolog.Logger
}

type configJson struct {
	TokenCacheTtl       int64  `json:"token_cache_ttl"`
	TokenCacheSize      int    `json:"token_cache_size"`
	CertificateCacheTtl int64  `json:"certificate_cache_ttl"`
	CertificateRegion   string `json:"certificate_region"`
	OauthUrl            string `json:"oauth_url"`
	JwtClaimMap         string `json:"jwt_claims_map"`
	JwtDuration         int64  `json:"jwt_duration"`
	HttpRetryAttempts   int    `json:"http_retry_attempts"`
	HttpRetryMinWait    int64  `json:"http_retry_min_wait"`
	HttpRetryMaxWait    int64  `json:"http_retry_max_wait"`
}

var (
	InitError      = errors.New("aws_sm_oauth: unable to initialize")
	HeaderNotFound = errors.New("aws_sm_oauth: required header not found")
)

const (
	CertificateSecretIdHeader = "X-Hasura-Certificate-Id"
	OauthClientIdHeader       = "X-Hasura-Oauth-Client-Id"
	BackendApiIdHeader        = "X-Hasura-Backend-Id"
)

func (provider AwsSmOauth) SecretFetcher(headers http.Header) (provider.SecretFetcher, error) {
	secretFetcher := secretFetcher{
		AwsSmOauth: &provider,
	}
	notFoundHeaders := make([]string, 0, 0)
	certificateSecretId := headers.Get(CertificateSecretIdHeader)
	if certificateSecretId == "" {
		notFoundHeaders = append(notFoundHeaders, CertificateSecretIdHeader)
	}
	secretFetcher.certificateSecretId = certificateSecretId
	oauthClientId := headers.Get(OauthClientIdHeader)
	if oauthClientId == "" {
		notFoundHeaders = append(notFoundHeaders, OauthClientIdHeader)
	}
	secretFetcher.oAuthClientId = oauthClientId
	backendApiId := headers.Get(BackendApiIdHeader)
	if backendApiId == "" {
		notFoundHeaders = append(notFoundHeaders, BackendApiIdHeader)
	}
	secretFetcher.backendApiId = backendApiId
	notFoundHeadersStr := strings.Join(notFoundHeaders, ", ")
	if len(notFoundHeaders) != 0 {
		return secretFetcher, fmt.Errorf("%s: %s", HeaderNotFound, notFoundHeadersStr)
	}
	return secretFetcher, nil
}

func (provider AwsSmOauth) DeleteConfigHeaders(headers *http.Header) {
	headers.Del(CertificateSecretIdHeader)
	headers.Del(OauthClientIdHeader)
	headers.Del(BackendApiIdHeader)
}

func Create(config map[string]interface{}, logger zerolog.Logger) (*AwsSmOauth, error) {
	jsonS, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", InitError, err)
	}
	var configJson configJson
	if err != nil {
		return nil, fmt.Errorf("%s: %w", InitError, err)
	}
	err = json.Unmarshal(jsonS, &configJson)
	sess, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("%s: error initializing secrets manager session: %w", InitError, err)
	}
	httpClient := getHttpClient(configJson.HttpRetryAttempts, configJson.HttpRetryMinWait, configJson.HttpRetryMaxWait)
	smClient := secretsmanager.New(sess, aws.NewConfig().
		WithRegion(configJson.CertificateRegion).
		WithHTTPClient(httpClient.StandardClient()))
	certificateCacheTtl := time.Duration(configJson.CertificateCacheTtl) * time.Second
	awsSecretsManagerCache, err := secretcache.New(
		func(c *secretcache.Cache) {
			c.CacheConfig.CacheItemTTL = certificateCacheTtl.Nanoseconds()
		},
		func(c *secretcache.Cache) {
			c.Client = smClient
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%s: error initializing secrets manager cache: %w", InitError, err)
	}
	tokenCacheTtl := time.Duration(configJson.TokenCacheTtl) * time.Second
	cache := expirable.NewLRU[string, string](configJson.TokenCacheSize, nil, tokenCacheTtl)
	oauthUrl, err := url.Parse(configJson.OauthUrl)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to parse oauth url: %w", InitError, err)
	}
	jwtClaimMap := make(map[string]interface{})
	err = json.Unmarshal([]byte(configJson.JwtClaimMap), &jwtClaimMap)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to parse jwt claim map: %w", InitError, err)
	}
	jwtDuration := time.Duration(configJson.JwtDuration) * time.Second
	conf := AwsSmOauth{
		awsSecretsManager: awsSecretsManagerCache,
		certificateRegion: configJson.CertificateRegion,
		cache:             cache,
		oAuthUrl:          *oauthUrl,
		jwtClaimMap:       jwtClaimMap,
		jwtDuration:       jwtDuration,
		httpClient:        httpClient,
		logger:            logger,
	}
	logConfig(conf, tokenCacheTtl, configJson.TokenCacheSize, logger)
	return &conf, nil
}

func getHttpClient(maxRetry int, minWaitSeconds int64, maxWaitSeconds int64) *retryablehttp.Client {
	minWaitDuration := time.Duration(minWaitSeconds) * time.Second
	maxWaitDuration := time.Duration(maxWaitSeconds) * time.Second
	retryableHttpClient := retryablehttp.NewClient()
	retryableHttpClient.RetryMax = maxRetry
	retryableHttpClient.RetryWaitMin = minWaitDuration
	retryableHttpClient.RetryWaitMax = maxWaitDuration
	return retryableHttpClient
}
