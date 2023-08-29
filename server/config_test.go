package server

import (
	"testing"
	"time"
)

func TestConfig_ParseValidAwsConfig(t *testing.T) {
	rawConfig := `
		{
			"providers": [
				{
					"type": "aws_secrets_manager",
					"cache_ttl": 3000
				}
			]
		}
	`
	expectedAwsConfig := AwsSecretStoreConfig{
		ProviderType: "aws_secrets_manager",
		CacheTtl:     time.Second * 3000,
	}
	expectedConfig := Config{
		Providers: []interface{}{
			expectedAwsConfig,
		},
	}
	actualResult, err := ParseConfig([]byte(rawConfig))
	if err != nil {
		t.Errorf("Failed with error %s", err)
	}
	if len(actualResult.Providers) != len(expectedConfig.Providers) {
		t.Errorf("Length %d and %d does not match", len(actualResult.Providers), len(expectedConfig.Providers))
	}
	if expectedAwsConfig != actualResult.Providers[0] {
		t.Errorf("Expected and actual AWS configs does not match")
	}
}
