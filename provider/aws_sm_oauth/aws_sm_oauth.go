package aws_sm_oauth

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/hasura/hasura-secret-refresh/provider"
	awssm "github.com/hasura/hasura-secret-refresh/provider/aws_secrets_manager"
	"github.com/rs/zerolog"
)

type AwsSmOAuth struct {
	cache             *expirable.LRU[RequestConfig, string]
	certificateRegion string
	awsSecretsManager *secretcache.Cache
	oAuthUrl          url.URL
	jwtClaimMap       map[string]interface{}
	jwtDuration       time.Duration
	httpClient        *retryablehttp.Client
	logger            zerolog.Logger
}

func (provider AwsSmOAuth) ParseRequestConfig(header http.Header) (provider.GetSecret, error) {
	config, err := GetRequestConfig(header)
	if err != nil {
		return nil, err
	}
	return func() (secret string, err error) {
		cachedToken, ok := provider.cache.Get(config)
		if ok {
			return cachedToken, nil
		}
		rsaPrivateKeyPemRaw, err := provider.awsSecretsManager.GetSecretString(config.CertificateSecretId)
		if err != nil {
			return
		}
		tokenString, err := CreateJwtToken(rsaPrivateKeyPemRaw, provider.jwtClaimMap, provider.jwtDuration, time.Now())
		if err != nil {
			return
		}
		oAuthRequest := GetOauthRequest(tokenString, config.BackendApiId, config.OAuthClientId, &provider.oAuthUrl)
		response, err := provider.httpClient.Do(oAuthRequest)
		if err != nil {
			return
		}
		accessToken, err := GetAccessTokenFromResponse(response)
		if err != nil {
			return
		}
		_ = provider.cache.Add(config, accessToken)
		return accessToken, nil
	}, nil
}

func (provider AwsSmOAuth) DeleteConfigHeaders(header *http.Header) {}

func CreateAwsSmOAuthProvider(
	certificateCacheTtl time.Duration,
	certificateRegion string,
	oAuthUrl url.URL,
	jwtClaimMap map[string]interface{},
	tokenCacheTtl time.Duration,
	tokenCacheSize int,
	jwtDuration time.Duration,
	httpRetryMinWait time.Duration,
	httpRetryMaxWait time.Duration,
	httpRetryAttempts int,
	logger zerolog.Logger,
) (provider AwsSmOAuth, err error) {
	sess, err := session.NewSession()
	if err != nil {
		return provider, fmt.Errorf("Error initializing secrets manager client: %s", err)
	}
	smClient := secretsmanager.New(sess, aws.NewConfig().WithRegion(certificateRegion))
	awsSecretsManagerCache, err := secretcache.New(
		func(c *secretcache.Cache) {
			c.CacheConfig.CacheItemTTL = awssm.GetCacheTtlFromDuration(certificateCacheTtl)
		},
		func(c *secretcache.Cache) {
			c.Client = smClient
		},
	)
	if err != nil {
		return
	}
	cache := expirable.NewLRU[RequestConfig, string](tokenCacheSize, nil, tokenCacheTtl)
	httpClient := getHttpClient(httpRetryAttempts, httpRetryMinWait, httpRetryMaxWait)
	provider = AwsSmOAuth{
		awsSecretsManager: awsSecretsManagerCache,
		certificateRegion: certificateRegion,
		cache:             cache,
		oAuthUrl:          oAuthUrl,
		jwtClaimMap:       jwtClaimMap,
		jwtDuration:       jwtDuration,
		httpClient:        httpClient,
		logger:            logger,
	}
	logConfig(provider, tokenCacheTtl, tokenCacheSize, logger)
	return
}

func getHttpClient(maxRetry int, minWaitSeconds time.Duration, maxWaitSeconds time.Duration) *retryablehttp.Client {
	retryableHttpClient := retryablehttp.NewClient()
	retryableHttpClient.RetryMax = maxRetry
	retryableHttpClient.RetryWaitMin = time.Duration(minWaitSeconds) * time.Second
	retryableHttpClient.RetryWaitMax = time.Duration(maxWaitSeconds) * time.Second
	return retryableHttpClient
}
