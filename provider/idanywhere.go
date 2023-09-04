package provider

import (
	"log"
	"net/url"
	"time"

	cache "github.com/patrickmn/go-cache"
)

type IdAnywhere struct {
	cache               *cache.Cache
	awsSm               *AwsSecretsManager
	certificateSecretId string
	oAuthUrl            url.URL
	oAuthClientId       string
	jwtClaimMap         map[string]string
}

func (provider IdAnywhere) GetSecret(requestConfig RequestConfig) (secret string, err error) {
	return
}

func CreateIdAnywhereProvider(
	secretsManagerCacheTtl time.Duration,
	certificateSecretId string,
	oAuthUrl url.URL,
	oAuthClientId string,
	jwtClaimMap map[string]string,
) (provider IdAnywhere, err error) {
	log.Printf("Creating IdAnywhere provider with AWS Secrets Manager cache TTL as %s, certificate secret id as %s, OAuth Url as %s, OAuth client id as %s",
		secretsManagerCacheTtl.String(),
		certificateSecretId,
		oAuthUrl.String(),
		oAuthClientId,
	)
	secresManagerProvider, err := CreateAwsSecretsManagerProvider(secretsManagerCacheTtl)
	if err != nil {
		return
	}
	cacheDefaultExpiration := 5 * time.Minute
	cachePurgeFrequency := time.Hour
	cache := cache.New(cacheDefaultExpiration, cachePurgeFrequency)
	return IdAnywhere{
		awsSm:               &secresManagerProvider,
		cache:               cache,
		certificateSecretId: certificateSecretId,
		oAuthUrl:            oAuthUrl,
		oAuthClientId:       oAuthClientId,
		jwtClaimMap:         jwtClaimMap,
	}, nil
}
