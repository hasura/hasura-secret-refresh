package aws_sm_oauth

import (
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/hasura/hasura-secret-refresh/provider"
	awssm "github.com/hasura/hasura-secret-refresh/provider/aws_secrets_manager"
	"github.com/rs/zerolog"
)

type AwsSmOAuth struct {
	cache             *expirable.LRU[RequestConfig, string]
	awsSecretsManager *secretcache.Cache
	oAuthUrl          url.URL
	jwtClaimMap       map[string]interface{}
	jwtDuration       time.Duration
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
		response, err := http.DefaultClient.Do(oAuthRequest)
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
	oAuthUrl url.URL,
	jwtClaimMap map[string]interface{},
	tokenCacheTtl time.Duration,
	tokenCacheSize int,
	jwtDuration time.Duration,
	logger zerolog.Logger,
) (provider AwsSmOAuth, err error) {
	awsSecretsManagerCache, err := secretcache.New(
		func(c *secretcache.Cache) {
			c.CacheConfig.CacheItemTTL = awssm.GetCacheTtlFromDuration(certificateCacheTtl)
		},
	)
	if err != nil {
		return
	}
	cache := expirable.NewLRU[RequestConfig, string](tokenCacheSize, nil, tokenCacheTtl)
	provider = AwsSmOAuth{
		awsSecretsManager: awsSecretsManagerCache,
		cache:             cache,
		oAuthUrl:          oAuthUrl,
		jwtClaimMap:       jwtClaimMap,
		jwtDuration:       jwtDuration,
		logger:            logger,
	}
	logConfig(provider, tokenCacheTtl, tokenCacheSize, logger)
	return
}
