package provider

import (
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	jwt "github.com/golang-jwt/jwt/v4"
	cache "github.com/patrickmn/go-cache"
)

type IdAnywhere struct {
	cache               *cache.Cache
	awsSecretsManager   *secretcache.Cache
	certificateSecretId string
	oAuthUrl            url.URL
	oAuthClientId       string
	jwtClaimMap         map[string]interface{}
}

func (provider IdAnywhere) GetSecret(requestConfig RequestConfig) (secret string, err error) {
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
	fmt.Println(tokenString)
	return
}

func CreateIdAnywhereProvider(
	secretsManagerCacheTtl time.Duration,
	certificateSecretId string,
	oAuthUrl url.URL,
	oAuthClientId string,
	jwtClaimMap map[string]interface{},
) (provider IdAnywhere, err error) {
	log.Printf("Creating IdAnywhere provider with AWS Secrets Manager cache TTL as %s, certificate secret id as %s, OAuth Url as %s, OAuth client id as %s",
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
	return IdAnywhere{
		awsSecretsManager:   awsSecretsManagerCache,
		cache:               cache,
		certificateSecretId: certificateSecretId,
		oAuthUrl:            oAuthUrl,
		oAuthClientId:       oAuthClientId,
		jwtClaimMap:         jwtClaimMap,
	}, nil
}
