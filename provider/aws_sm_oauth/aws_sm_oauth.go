package aws_sm_oauth

import (
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"github.com/hashicorp/golang-lru/v2/expirable"
	awssm "github.com/hasura/hasura-secret-refresh/provider/aws_secrets_manager"
	"github.com/rs/zerolog"
)

type AwsSmOAuth struct {
	cache               *expirable.LRU[string, string]
	awsSecretsManager   *secretcache.Cache
	certificateSecretId string
	oAuthUrl            url.URL
	oAuthClientId       string
	jwtClaimMap         map[string]interface{}
	jwtDuration         time.Duration
	logger              zerolog.Logger
}

func (provider AwsSmOAuth) GetSecret(secretId string) (secret string, err error) {
	cachedToken, ok := provider.cache.Get(secretId)
	if ok {
		return cachedToken, nil
	}
	rsaPrivateKeyPemRaw, err := provider.awsSecretsManager.GetSecretString(provider.certificateSecretId)
	if err != nil {
		return
	}
	tokenString, err := CreateJwtToken(rsaPrivateKeyPemRaw, provider.jwtClaimMap, provider.jwtDuration, time.Now())
	if err != nil {
		return
	}
	oAuthRequest := GetOauthRequest(tokenString, secretId, provider.oAuthClientId, &provider.oAuthUrl)
	response, err := http.DefaultClient.Do(oAuthRequest)
	if err != nil {
		return
	}
	accessToken, err := GetAccessTokenFromResponse(response)
	if err != nil {
		return
	}
	_ = provider.cache.Add(secretId, accessToken)
	return accessToken, nil
}

func CreateAwsSmOAuthProvider(
	certificateCacheTtl time.Duration,
	certificateSecretId string,
	oAuthUrl url.URL,
	oAuthClientId string,
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
	cache := expirable.NewLRU[string, string](tokenCacheSize, nil, tokenCacheTtl)
	provider = AwsSmOAuth{
		awsSecretsManager:   awsSecretsManagerCache,
		cache:               cache,
		certificateSecretId: certificateSecretId,
		oAuthUrl:            oAuthUrl,
		oAuthClientId:       oAuthClientId,
		jwtClaimMap:         jwtClaimMap,
		jwtDuration:         jwtDuration,
		logger:              logger,
	}
	logConfig(provider, tokenCacheTtl, tokenCacheSize, logger)
	return
}
