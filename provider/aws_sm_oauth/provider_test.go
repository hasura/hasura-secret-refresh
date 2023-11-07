package aws_sm_oauth

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog"
)

type mockRoundTripper struct {
	t *testing.T
}

func (m mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() == "https://secretsmanager.us-east-2.amazonaws.com/" {
		b, _ := io.ReadAll(r.Body)
		reqBody := make(map[string]string)
		json.Unmarshal(b, &reqBody)
		secretString := ""
		if reqBody["SecretId"] == "testCert" {
			secretString = testSslCert
		} else {
			secretString = testRsaPrivateKeyPem
		}
		respJson := []byte(`{
			"ARN": "arn:aws:secretsmanager:us-east-2:343343343343:secret:testCert-Nb1db1",
			"CreatedDate": 1699254319,
			"VersionId": "AWSCURRENT",
			"VersionStages": [ "AWSCURRENT" ],
			"VersionIdsToStages": { 
				"ef31e651-d4ba-4994-82b6-7fb5ea9daf39" : [ "AWSCURRENT" ]
			 }
		 }`)
		jsonP := make(map[string]interface{})
		json.Unmarshal([]byte(respJson), &jsonP)
		jsonP["SecretString"] = secretString
		jsonP["Name"] = reqBody["SecretId"]
		respJson, _ = json.Marshal(jsonP)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respJson))),
		}, nil
	} else if r.URL.String() == "http://localhost:8090/oauth" {
		respJson := []byte(`{
			"access_token": "random_access_token_123"
		 }`)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respJson))),
		}, nil
	}
	m.t.Fatalf("Unexpected request")
	return nil, nil
}

var mockHttpClient = http.Client{
	Transport: mockRoundTripper{},
}

func mockAwsSmClient(httpClient *retryablehttp.Client) *secretcache.Cache {
	sess, _ := session.NewSession()
	smClient := secretsmanager.New(sess, aws.NewConfig().
		WithRegion("us-east-2").
		WithCredentials(credentials.AnonymousCredentials).
		WithHTTPClient(httpClient.StandardClient()))
	certificateCacheTtl := time.Duration(300) * time.Second
	awsSecretsManagerCache, _ := secretcache.New(
		func(c *secretcache.Cache) {
			c.CacheConfig.CacheItemTTL = certificateCacheTtl.Nanoseconds()
		},
		func(c *secretcache.Cache) {
			c.Client = smClient
		},
	)
	return awsSecretsManagerCache
}

func Test_AwsSmOauthProvider(t *testing.T) {
	testConfig := map[string]interface{}{
		"type":                  "proxy_awssm_oauth",
		"certificate_cache_ttl": 300,
		"certificate_region":    "us-east-2",
		"token_cache_ttl":       300,
		"token_cache_size":      10,
		"oauth_url":             "http://localhost:8090/oauth",
		"jwt_claims_map":        `{"extra_claim":"extra_claim"}`,
		"jwt_duration":          300,
		"http_retry_attempts":   0,
		"http_retry_min_wait":   1,
		"http_retry_max_wait":   1,
	}
	provider, err := Create(testConfig, zerolog.Nop())
	if err != nil {
		t.Fatalf("Unable to initialize provider: %s", err)
	}
	provider.httpClient.HTTPClient = &mockHttpClient
	provider.awsSecretsManager = mockAwsSmClient(provider.httpClient)
	headers := http.Header(map[string][]string{
		"X-Hasura-Certificate-Id":  []string{"testCert"},
		"X-Hasura-Backend-Id":      []string{"testBackendId"},
		"X-Hasura-Oauth-Client-Id": []string{"testOauthClientId"},
		"X-Hasura-Private-Key-Id":  []string{"testPrivateKeyId"},
		"Some-Additional-Header":   []string{"random_val123"},
	})
	fetcher, err := provider.SecretFetcher(headers)
	if err != nil {
		t.Fatalf("Unable to retrieve fetcher: %s", err)
	}
	provider.DeleteConfigHeaders(&headers)
	if len(headers) != 1 {
		t.Fatalf("Config headers were not deleted properly")
	}
	additionalHeader := headers.Get("Some-Additional-Header")
	if additionalHeader != "random_val123" {
		t.Fatalf("Additional header was removed/modified")
	}
	secretStr, err := fetcher.FetchSecret()
	if err != nil {
		t.Fatalf("Failed to fetch secret: %s", err)
	}
	if secretStr != "random_access_token_123" {
		t.Fatalf("Expected secret string to be %s but got %s", "random_access_token_123", secretStr)
	}
}
