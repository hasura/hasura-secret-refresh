package provider

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	jwt "github.com/golang-jwt/jwt/v4"
	cache "github.com/patrickmn/go-cache"
)

type AwsSmOAuth struct {
	cache               *cache.Cache
	awsSecretsManager   *secretcache.Cache
	certificateSecretId string
	oAuthUrl            url.URL
	oAuthClientId       string
	jwtClaimMap         map[string]interface{}
}

func (provider AwsSmOAuth) GetSecret(requestConfig RequestConfig) (secret string, err error) {
	rsaPrivateKeyPemRaw, err := provider.awsSecretsManager.GetSecretString(provider.certificateSecretId)
	if err != nil {
		return
	}
	rsaPrivateKeyPem, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaPrivateKeyPemRaw))
	if err != nil {
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(provider.jwtClaimMap))
	tokenString, err := token.SignedString(rsaPrivateKeyPem)
	if err != nil {
		return
	}
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_id", provider.oAuthClientId)
	data.Set("client_assertion", tokenString)
	data.Set("resource", requestConfig.SecretId)
	r, _ := http.NewRequest(http.MethodPost, provider.oAuthUrl.String(), strings.NewReader(data.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Accept", "application/x-www-form-url-encoded")
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
	secret, _ = respJson["access_token"].(string)
	return
}

func CreateAwsSmOAuthProvider(
	secretsManagerCacheTtl time.Duration,
	certificateSecretId string,
	oAuthUrl url.URL,
	oAuthClientId string,
	jwtClaimMap map[string]interface{},
) (provider AwsSmOAuth, err error) {
	log.Printf("Creating Aws Secrets Manager + OAuth provider with AWS Secrets Manager cache TTL as %s, certificate secret id as %s, OAuth Url as %s, OAuth client id as %s",
		secretsManagerCacheTtl.String(),
		certificateSecretId,
		oAuthUrl.String(),
		oAuthClientId,
	)
	if err != nil {
		return
	}
	awsSecretsManagerCache, err := secretcache.New(
		func(c *secretcache.Cache) {
			c.CacheConfig.CacheItemTTL = GetCacheTtlFromDuration(secretsManagerCacheTtl)
		},
	)
	if err != nil {
		return
	}
	cacheDefaultExpiration := 5 * time.Minute
	cachePurgeFrequency := time.Hour
	cache := cache.New(cacheDefaultExpiration, cachePurgeFrequency)
	return AwsSmOAuth{
		awsSecretsManager:   awsSecretsManagerCache,
		cache:               cache,
		certificateSecretId: certificateSecretId,
		oAuthUrl:            oAuthUrl,
		oAuthClientId:       oAuthClientId,
		jwtClaimMap:         jwtClaimMap,
	}, nil
}
