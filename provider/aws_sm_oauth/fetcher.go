package aws_sm_oauth

import (
	"fmt"
	"strings"
	"time"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

type secretFetcher struct {
	*AwsSmOauth
	certificateSecretId string
	privateKeySecretId  string
	backendApiId        string
	oAuthClientId       string
}

var (
	UnableToFetch = "aws_sm_oauth: unable to fetch secret"
)

func (fetcher secretFetcher) FetchSecret() (string, error) {
	cacheKey := fetcher.getCacheKey()
	cachedToken, ok := fetcher.cache.Get(cacheKey)
	if ok {
		return cachedToken, nil
	}
	jwtToken, err := fetcher.createJwtToken()
	if err != nil {
		return "", err
	}
	accessToken, err := fetcher.getAccessToken(jwtToken)
	if err != nil {
		return "", err
	}
	_ = fetcher.cache.Add(cacheKey, accessToken)
	return accessToken, nil
}

func (fetcher secretFetcher) getAccessToken(jwtToken string) (string, error) {
	oAuthMethod, oAuthFormData, oAuthHeader := getOauthRequest(jwtToken, fetcher.backendApiId, fetcher.oAuthClientId, &fetcher.oAuthUrl)
	oAuthRequest, err := retryablehttp.NewRequest(oAuthMethod, fetcher.oAuthUrl.String(), strings.NewReader(oAuthFormData.Encode()))
	if err != nil {
		return "", fmt.Errorf("%s: Unable to create oauth request: %w", UnableToFetch, err)
	}
	oAuthRequest.Header = oAuthHeader
	logOauthRequest(fetcher.oAuthUrl, oAuthMethod, oAuthFormData, oAuthHeader, "Sending request to oauth endpoint", fetcher.logger)
	response, err := fetcher.httpClient.Do(oAuthRequest)
	if err != nil {
		return "", fmt.Errorf("%s: Unable perform oauth request: %w", UnableToFetch, err)
	}
	logOAuthResponse(response, "Response from oauth endpoint", fetcher.logger)
	if response.StatusCode != 200 {
		return "", fmt.Errorf("Did not receive 200 response from oauth server. Received: status code: %d", response.StatusCode)
	}
	accessToken, err := getAccessTokenFromResponse(response, fetcher.logger)
	if err != nil {
		return "", fmt.Errorf("%s: Unable to get access token from oauth response: %w", UnableToFetch, err)
	}
	return accessToken, nil
}

func (fetcher secretFetcher) createJwtToken() (string, error) {
	rsaPrivateKeyPemRaw, err := fetcher.awsSecretsManager.GetSecretString(fetcher.privateKeySecretId)
	if err != nil {
		return "", fmt.Errorf("%s: unable to retrieve private key from aws secrets manager: %w", UnableToFetch, err)
	}
	fetcher.logger.Debug().Str("aws_secret_id", fetcher.privateKeySecretId).Str("aws_response", rsaPrivateKeyPemRaw).Msg("Response from aws secrets manager")
	sslCert, err := fetcher.awsSecretsManager.GetSecretString(fetcher.certificateSecretId)
	if err != nil {
		return "", fmt.Errorf("%s: unable to retrieve certificate from aws secrets manager: %w", UnableToFetch, err)
	}
	fetcher.logger.Debug().Str("aws_secret_id", fetcher.certificateSecretId).Str("aws_response", sslCert).Msg("Response from aws secrets manager")
	tokenString, err := createJwtToken(rsaPrivateKeyPemRaw, fetcher.jwtClaimMap,
		fetcher.jwtDuration, time.Now(), fetcher.oAuthClientId, sslCert,
	)
	if err != nil {
		return "", fmt.Errorf("%s: unable to create jwt token: %w", UnableToFetch, err)
	}
	return tokenString, nil
}

func (fetcher secretFetcher) getCacheKey() string {
	return fmt.Sprintf("%s_%s_%s_%s",
		fetcher.certificateSecretId,
		fetcher.backendApiId,
		fetcher.oAuthClientId,
		fetcher.privateKeySecretId,
	)
}
