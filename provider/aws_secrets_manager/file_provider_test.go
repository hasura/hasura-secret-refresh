package aws_secrets_manager

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSecretsManager mocks the AWS Secrets Manager client
type MockSecretsManager struct {
	mock.Mock
}

func (m *MockSecretsManager) GetSecretValue(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*secretsmanager.GetSecretValueOutput), args.Error(1)
}

func TestCreateAwsSecretsManagerFile_ValidConfig(t *testing.T) {
	logger := zerolog.Nop()

	config := map[string]interface{}{
		"region":    "us-east-1",
		"path":      "/tmp/test-secret",
		"secret_id": "test-secret",
		"refresh":   30,
	}

	provider, err := CreateAwsSecretsManagerFile(config, logger)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/test-secret", provider.filePath)
	assert.Equal(t, "test-secret", provider.secretId)
	assert.Equal(t, 30*time.Second, provider.refreshInterval)
	assert.Equal(t, "", provider.template)
	assert.False(t, provider.secretTransform.HasTransformations())
}

func TestCreateAwsSecretsManagerFile_MissingRegion(t *testing.T) {
	logger := zerolog.Nop()

	config := map[string]interface{}{
		"path":      "/tmp/test-secret",
		"secret_id": "test-secret",
		"refresh":   30,
	}

	_, err := CreateAwsSecretsManagerFile(config, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required configs not found")
}

func TestCreateAwsSecretsManagerFile_MissingPath(t *testing.T) {
	logger := zerolog.Nop()

	config := map[string]interface{}{
		"region":    "us-east-1",
		"secret_id": "test-secret",
		"refresh":   30,
	}

	_, err := CreateAwsSecretsManagerFile(config, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required configs not found")
}

func TestCreateAwsSecretsManagerFile_MissingSecretId(t *testing.T) {
	logger := zerolog.Nop()

	config := map[string]interface{}{
		"region":  "us-east-1",
		"path":    "/tmp/test-secret",
		"refresh": 30,
	}

	_, err := CreateAwsSecretsManagerFile(config, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required configs not found")
}

func TestCreateAwsSecretsManagerFile_MissingRefresh(t *testing.T) {
	logger := zerolog.Nop()

	config := map[string]interface{}{
		"region":    "us-east-1",
		"path":      "/tmp/test-secret",
		"secret_id": "test-secret",
	}

	_, err := CreateAwsSecretsManagerFile(config, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required configs not found")
}

func TestCreateAwsSecretsManagerFile_WithTemplate(t *testing.T) {
	logger := zerolog.Nop()

	config := map[string]interface{}{
		"region":    "us-east-1",
		"path":      "/tmp/test-secret",
		"secret_id": "test-secret",
		"refresh":   30,
		"template":  "Bearer ##secret1.token##",
	}

	provider, err := CreateAwsSecretsManagerFile(config, logger)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer ##secret1.token##", provider.template)
	assert.False(t, provider.secretTransform.HasTransformations())
}

func TestCreateAwsSecretsManagerFile_WithTransform(t *testing.T) {
	logger := zerolog.Nop()

	config := map[string]interface{}{
		"region":    "us-east-1",
		"path":      "/tmp/test-secret",
		"secret_id": "test-secret",
		"refresh":   30,
		"transform": map[string]interface{}{
			"mode": "keep_all",
			"key_mappings": []interface{}{
				map[string]interface{}{"from": "username", "to": "user"},
			},
		},
	}

	provider, err := CreateAwsSecretsManagerFile(config, logger)
	assert.NoError(t, err)
	assert.Equal(t, "", provider.template)
	assert.True(t, provider.secretTransform.HasTransformations())
}

func TestCreateAwsSecretsManagerFile_BothTemplateAndTransform(t *testing.T) {
	logger := zerolog.Nop()

	config := map[string]interface{}{
		"region":    "us-east-1",
		"path":      "/tmp/test-secret",
		"secret_id": "test-secret",
		"refresh":   30,
		"template":  "Bearer ##secret1.token##",
		"transform": map[string]interface{}{
			"mode": "keep_all",
			"key_mappings": []interface{}{
				map[string]interface{}{"from": "username", "to": "user"},
			},
		},
	}

	_, err := CreateAwsSecretsManagerFile(config, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Only one of 'template' or 'transform' can be configured")
}

func TestAwsSecretsManagerFile_getSecret_WithTransform(t *testing.T) {
	logger := zerolog.Nop()

	tests := []struct {
		name            string
		secretValue     string
		transformConfig map[string]interface{}
		expectedResult  string
		isJSON          bool
	}{
		{
			name:            "no transformation - return original",
			secretValue:     `{"username": "admin", "password": "secret123"}`,
			transformConfig: map[string]interface{}{},
			expectedResult:  `{"username": "admin", "password": "secret123"}`,
			isJSON:          true,
		},
		{
			name:        "simple key mapping - keep all mode",
			secretValue: `{"username": "admin", "password": "secret123"}`,
			transformConfig: map[string]interface{}{
				"mode": "keep_all",
				"key_mappings": []interface{}{
					map[string]interface{}{"from": "username", "to": "user"},
					map[string]interface{}{"from": "password", "to": "pass"},
				},
			},
			expectedResult: `{"pass":"secret123","user":"admin"}`,
			isJSON:         true,
		},
		{
			name:        "simple key mapping - transformed only mode",
			secretValue: `{"username": "admin", "password": "secret123", "host": "localhost"}`,
			transformConfig: map[string]interface{}{
				"mode": "transformed_only",
				"key_mappings": []interface{}{
					map[string]interface{}{"from": "username", "to": "user"},
					map[string]interface{}{"from": "password", "to": "pass"},
				},
			},
			expectedResult: `{"pass":"secret123","user":"admin"}`,
			isJSON:         true,
		},
		{
			name:        "non-JSON secret - return original",
			secretValue: "plain-text-secret",
			transformConfig: map[string]interface{}{
				"mode": "keep_all",
				"key_mappings": []interface{}{
					map[string]interface{}{"from": "username", "to": "user"},
				},
			},
			expectedResult: "plain-text-secret",
			isJSON:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config with transform
			config := map[string]interface{}{
				"region":    "us-east-1",
				"path":      "/tmp/test-secret",
				"secret_id": "test-secret",
				"refresh":   30,
			}

			// Add transform config if provided
			if len(tt.transformConfig) > 0 {
				config["transform"] = tt.transformConfig
			}

			// Create provider using config
			provider, err := CreateAwsSecretsManagerFile(config, logger)
			assert.NoError(t, err)

			// Setup mock
			mockSM := &MockSecretsManager{}
			secretOutput := &secretsmanager.GetSecretValueOutput{
				SecretString: &tt.secretValue,
			}
			mockSM.On("GetSecretValue", mock.AnythingOfType("*secretsmanager.GetSecretValueInput")).Return(secretOutput, nil)

			// Replace the real secrets manager with mock
			provider.secretsManager = mockSM

			// Test getSecret
			result, err := provider.getSecret()
			assert.NoError(t, err)

			if tt.isJSON {
				assert.JSONEq(t, tt.expectedResult, result)
			} else {
				assert.Equal(t, tt.expectedResult, result)
			}

			mockSM.AssertExpectations(t)
		})
	}
}

func TestAwsSecretsManagerFile_getSecret_WithTemplate(t *testing.T) {
	logger := zerolog.Nop()

	tests := []struct {
		name           string
		secretValue    string
		template       string
		expectedResult string
	}{
		{
			name:           "simple template substitution",
			secretValue:    `{"token": "abc123"}`,
			template:       "Bearer ##secret1.token##",
			expectedResult: "Bearer abc123",
		},
		{
			name:           "multiple template substitutions",
			secretValue:    `{"user": "admin", "pass": "secret"}`,
			template:       "##secret1.user##:##secret1.pass##",
			expectedResult: "admin:secret",
		},
		{
			name:           "no template - return original",
			secretValue:    `{"token": "abc123"}`,
			template:       "",
			expectedResult: `{"token": "abc123"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config with template
			config := map[string]interface{}{
				"region":    "us-east-1",
				"path":      "/tmp/test-secret",
				"secret_id": "test-secret",
				"refresh":   30,
			}

			if tt.template != "" {
				config["template"] = tt.template
			}

			// Create provider using config
			provider, err := CreateAwsSecretsManagerFile(config, logger)
			assert.NoError(t, err)

			// Setup mock
			mockSM := &MockSecretsManager{}
			secretOutput := &secretsmanager.GetSecretValueOutput{
				SecretString: &tt.secretValue,
			}
			mockSM.On("GetSecretValue", mock.AnythingOfType("*secretsmanager.GetSecretValueInput")).Return(secretOutput, nil)

			// Replace the real secrets manager with mock
			provider.secretsManager = mockSM

			// Test getSecret
			result, err := provider.getSecret()
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)

			mockSM.AssertExpectations(t)
		})
	}
}

func TestAwsSecretsManagerFile_Refresh(t *testing.T) {
	logger := zerolog.Nop()
	tempFile := "/tmp/test-refresh-secret"

	// Create config
	config := map[string]interface{}{
		"region":    "us-east-1",
		"path":      tempFile,
		"secret_id": "test-secret",
		"refresh":   30,
	}

	// Create provider using config
	provider, err := CreateAwsSecretsManagerFile(config, logger)
	assert.NoError(t, err)

	// Setup mock
	mockSM := &MockSecretsManager{}
	secretValue := "refreshed-secret"
	mockSM.On("GetSecretValue", mock.AnythingOfType("*secretsmanager.GetSecretValueInput")).
		Return(&secretsmanager.GetSecretValueOutput{
			SecretString: &secretValue,
		}, nil)

	// Replace the real secrets manager with mock and add mutex
	provider.secretsManager = mockSM
	provider.mu = &sync.Mutex{}

	// Test refresh
	err = provider.Refresh()
	assert.NoError(t, err)

	// Verify file was written
	content, err := os.ReadFile(tempFile)
	assert.NoError(t, err)
	assert.Equal(t, secretValue, string(content))

	// Cleanup
	os.Remove(tempFile)
	mockSM.AssertExpectations(t)
}

func TestAwsSecretsManagerFile_FileName(t *testing.T) {
	logger := zerolog.Nop()

	config := map[string]interface{}{
		"region":    "us-east-1",
		"path":      "/tmp/test-secret",
		"secret_id": "test-secret",
		"refresh":   30,
	}

	provider, err := CreateAwsSecretsManagerFile(config, logger)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/test-secret", provider.FileName())
}
