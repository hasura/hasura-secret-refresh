package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/golang-lru/v2/expirable"
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
	debugLogger := provider.logger
	defer func() {
		if err != nil {
			debugLogger.Debug().Err(err).Msg("error completing provider flow")
		} else {
			debugLogger.Debug().Msg("Completed aws+oauth flow")
		}
	}()
	cachedToken, ok := provider.cache.Get(secretId)
	if ok {
		return cachedToken, nil
	}
	rsaPrivateKeyPemRaw, err := provider.awsSecretsManager.GetSecretString(provider.certificateSecretId)
	debugLogger = debugLogger.With().Str("aws_secret_val", rsaPrivateKeyPemRaw).Logger()
	if err != nil {
		return
	}
	tokenString, err := provider.createJwtToken(rsaPrivateKeyPemRaw)
	debugLogger = debugLogger.With().Str("created_jwt_token", tokenString).Logger()
	if err != nil {
		return
	}
	accessToken, err := provider.getTokenFromOAuthCall(secretId, tokenString, provider.logger)
	debugLogger = debugLogger.With().Str("token_from_oauth", accessToken).Logger()
	if err != nil {
		return
	}
	_ = provider.cache.Add(secretId, accessToken)
	return accessToken, nil
}

func (provider AwsSmOAuth) createJwtToken(rsaPrivateKeyPemRaw string) (string, error) {
	rsaPrivateKeyPem, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaPrivateKeyPemRaw))
	if err != nil {
		return "", err
	}
	jwtDuration := provider.jwtDuration
	currentJwtClaim := make(map[string]interface{})
	jwtExp := time.Now().Add(jwtDuration).Unix()
	for k, v := range provider.jwtClaimMap {
		currentJwtClaim[k] = v
	}
	currentJwtClaim["exp"] = jwtExp
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(currentJwtClaim))
	tokenString, err := token.SignedString(rsaPrivateKeyPem)
	if err != nil {
		return tokenString, err
	}
	return tokenString, nil
}

func (provider AwsSmOAuth) getTokenFromOAuthCall(
	secretId string,
	tokenString string,
	logger zerolog.Logger,
) (token string, err error) {
	defer func() {
		if err != nil {
			logger.Debug().Err(err).Msg("Error completing OAuth flow")
		} else {
			logger.Debug().Msg("OAuth flow completed")
		}
	}()
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_id", provider.oAuthClientId)
	data.Set("client_assertion", tokenString)
	data.Set("resource", secretId)
	r, _ := http.NewRequest(http.MethodPost, provider.oAuthUrl.String(), strings.NewReader(data.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Accept", "application/x-www-form-url-encoded")
	formDataDict := zerolog.Dict()
	for k, _ := range data {
		formDataDict = formDataDict.Str(k, data.Get(k))
	}
	logger = logger.With().Dict("form_data", formDataDict).Logger()
	headerDict := zerolog.Dict()
	for k, _ := range r.Header {
		headerDict = headerDict.Str(k, r.Header.Get(k))
	}
	logger = logger.With().Dict("headers", headerDict).Logger()
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	respJson := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&respJson)
	if err != nil {
		return
	}
	token, ok := respJson["access_token"].(string)
	if !ok {
		return token, errors.New(fmt.Sprintf("Error converting token to string"))
	}
	return
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
	logger.Info().
		Str("certificate_cache_ttl", certificateCacheTtl.String()).
		Str("certificate_secret_id", certificateSecretId).
		Str("oauth_url", oAuthUrl.String()).
		Str("oauth_client_id", oAuthClientId).
		Str("token_cache_ttl", tokenCacheTtl.String()).
		Int("token_cache_size", tokenCacheSize).
		Str("jwt_duration", jwtDuration.String()).
		Msg("Creating provider")
	awsSecretsManagerCache, err := secretcache.New(
		func(c *secretcache.Cache) {
			c.CacheConfig.CacheItemTTL = GetCacheTtlFromDuration(certificateCacheTtl)
		},
	)
	if err != nil {
		return
	}
	cache := expirable.NewLRU[string, string](tokenCacheSize, nil, tokenCacheTtl)
	return AwsSmOAuth{
		awsSecretsManager:   awsSecretsManagerCache,
		cache:               cache,
		certificateSecretId: certificateSecretId,
		oAuthUrl:            oAuthUrl,
		oAuthClientId:       oAuthClientId,
		jwtClaimMap:         jwtClaimMap,
		jwtDuration:         jwtDuration,
		logger:              logger,
	}, nil
}
