package aws_secrets_manager

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hasura/hasura-secret-refresh/template"
	"github.com/rs/zerolog"
)

type AwsSecretsManagerFile struct {
	refreshInterval time.Duration
	secretsManager  *secretsmanager.SecretsManager
	filePath        string
	secretId        string
	template        string
	// i would like to implement a mapper
	// that would map secret key to a new key
	// what would that be?
	keyMapper map[string]string

	logger zerolog.Logger
	mu     *sync.Mutex
}

func CreateAwsSecretsManagerFile(config map[string]interface{}, logger zerolog.Logger) (AwsSecretsManagerFile, error) {
	regionI, found := config["region"]
	if !found {
		logger.Error().Msg("aws_secrets_manager_file: Config 'region' not found")
		return AwsSecretsManagerFile{}, fmt.Errorf("required configs not found")
	}
	region, ok := regionI.(string)
	if !ok {
		logger.Error().Msg("aws_secrets_manager_file: 'region' must be a string")
		return AwsSecretsManagerFile{}, fmt.Errorf("config not valid")
	}
	filePathI, found := config["path"]
	if !found {
		logger.Error().Msg("aws_secrets_manager_file: Config 'path' not found")
		return AwsSecretsManagerFile{}, fmt.Errorf("required configs not found")
	}
	filePath, ok := filePathI.(string)
	if !ok {
		logger.Error().Msg("aws_secrets_manager_file: 'path' must be a string")
		return AwsSecretsManagerFile{}, fmt.Errorf("config not valid")
	}
	secretIdI, found := config["secret_id"]
	if !found {
		logger.Error().Msg("aws_secrets_manager_file: Config 'secret_id' not found")
		return AwsSecretsManagerFile{}, fmt.Errorf("required configs not found")
	}
	secretId, ok := secretIdI.(string)
	if !ok {
		logger.Error().Msg("aws_secrets_manager_file: 'secret_id' must be a string")
		return AwsSecretsManagerFile{}, fmt.Errorf("config not valid")
	}
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println("Error initializing secrets manager session")
	}
	refreshIntervalI, found := config["refresh"]
	if !found {
		logger.Error().Msg("aws_secrets_manager_file: Config 'refresh' not found")
		return AwsSecretsManagerFile{}, fmt.Errorf("required configs not found")
	}
	refreshIntervalInt, ok := refreshIntervalI.(int)
	if !ok {
		logger.Error().Msg("aws_secrets_manager_file: 'refresh' must be an integer")
		return AwsSecretsManagerFile{}, fmt.Errorf("config not valid")
	}
	refreshInterval := time.Duration(refreshIntervalInt) * time.Second
	smClient := secretsmanager.New(sess, aws.NewConfig().
		WithRegion(region))
	secretTemplate := ""
	secretTemplateI, ok := config["template"]
	if ok {
		secretTemplate, ok = secretTemplateI.(string)
		if !ok {
			logger.Error().Msg("aws_secrets_manager_file: 'template' must be a string")
			return AwsSecretsManagerFile{}, fmt.Errorf("config not valid")
		}
	}

	// Add key mapper configuration
	keyMapper := make(map[string]string)
	keyMapperI, found := config["key_mapper"]
	if found {
		keyMapperConfig, ok := keyMapperI.(map[string]interface{})
		if !ok {
			logger.Error().Msg("aws_secrets_manager_file: 'key_mapper' must be a map")
			return AwsSecretsManagerFile{}, fmt.Errorf("config not valid")
		}
		for oldKey, newKeyI := range keyMapperConfig {
			newKey, ok := newKeyI.(string)
			if !ok {
				logger.Error().Msgf("aws_secrets_manager_file: key_mapper value for '%s' must be a string", oldKey)
				return AwsSecretsManagerFile{}, fmt.Errorf("config not valid")
			}
			keyMapper[oldKey] = newKey
		}
	}
	awsSm := AwsSecretsManagerFile{
		refreshInterval: refreshInterval,
		filePath:        filePath,
		secretsManager:  smClient,
		secretId:        secretId,
		logger:          logger,
		template:        secretTemplate,
		keyMapper:       keyMapper,
		mu:              &sync.Mutex{},
	}
	logger.Info().
		Str("refresh", refreshInterval.String()).
		Str("file_path", filePath).
		Str("secret_id", secretId).
		Msg("Creating provider")
	return awsSm, err
}

func (provider AwsSecretsManagerFile) Start() {
	err := os.WriteFile(provider.filePath, []byte(""), 0777)
	if err != nil {
		provider.logger.Err(err).Msgf("aws_secrets_manager_file: Error occurred while writing to file %s", provider.filePath)
	}
	for {
		secret, err := provider.getSecret()
		if err != nil {
			time.Sleep(provider.refreshInterval)
			continue
		}
		err = provider.writeFile(secret)
		if err != nil {
			time.Sleep(provider.refreshInterval)
			continue
		}
		provider.logger.Info().Msgf("aws_secrets_manager_file: Successfully fetched secret %s. Fetching again in %s", provider.secretId, provider.refreshInterval)
		time.Sleep(provider.refreshInterval)
	}
}

func (provider AwsSecretsManagerFile) Refresh() error {
	provider.logger.Info().Msgf("aws_secrets_manager_file: Refresh invoked for secret %s", provider.secretId)
	secret, err := provider.getSecret()
	if err != nil {
		return err
	}
	err = provider.writeFile(secret)
	if err != nil {
		return err
	}
	provider.logger.Info().Msgf("aws_secrets_manager_file: Successfully refreshed secret %s upon invocation", provider.secretId)
	return nil
}

func (provider AwsSecretsManagerFile) FileName() string {
	return provider.filePath
}

func (provider AwsSecretsManagerFile) getSecret() (string, error) {
	provider.logger.Info().Msgf("aws_secrets_manager_file: Fetching secret %s", provider.secretId)
	res, err := provider.secretsManager.GetSecretValue(
		&secretsmanager.GetSecretValueInput{
			SecretId: &provider.secretId,
		},
	)
	if err != nil {
		provider.logger.Err(err).Msgf("aws_secrets_manager_file: Error occurred while retrieving secret '%s' from aws secrets manager", provider.secretId)
		return "", err
	}
	secretString := *res.SecretString

	// Apply key mapping if configured
	if len(provider.keyMapper) > 0 {
		secretString, err = provider.applyKeyMapping(secretString)
		if err != nil {
			provider.logger.Err(err).Msg("aws_secrets_manager_file: Error applying key mapping")
			return "", err
		}
	}
	if provider.template != "" {
		templ := template.Template{Templ: provider.template, Logger: provider.logger}
		secretString = templ.Substitute(secretString)
	}
	return secretString, nil
}

func (provider AwsSecretsManagerFile) writeFile(secretString string) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	err := os.WriteFile(provider.filePath, []byte(secretString), 0777)
	if err != nil {
		provider.logger.Err(err).Msgf("aws_secrets_manager_file: Error occurred while writing secret %s to file %s", provider.secretId, provider.filePath)
		return err
	}
	return nil
}

// Add this new method
func (provider AwsSecretsManagerFile) applyKeyMapping(secretString string) (string, error) {
	var secretData map[string]interface{}
	err := json.Unmarshal([]byte(secretString), &secretData)
	if err != nil {
		provider.logger.Err(err).Msg("aws_secrets_manager_file: Failed to parse secret as JSON for key mapping")
		return secretString, nil // Return original if not JSON
	}

	mappedData := make(map[string]interface{})
	for originalKey, value := range secretData {
		mapped := false
		if newKey, exists := provider.keyMapper[originalKey]; exists {
			mappedData[newKey] = value
			provider.logger.Debug().Msgf("aws_secrets_manager_file: Mapped key '%s' to '%s'", originalKey, newKey)
		} else {
			// Try lowercase match for case-insensitive mapping
			for mapperKey, newKey := range provider.keyMapper {
				if strings.ToLower(mapperKey) == strings.ToLower(originalKey) {
					mappedData[newKey] = value
					provider.logger.Debug().Msgf("aws_secrets_manager_file: Mapped key '%s' to '%s' (case-insensitive)", originalKey, newKey)
					mapped = true
					break
				}
			}
		}
		if !mapped {
			mappedData[originalKey] = value
		}
	}

	mappedBytes, err := json.Marshal(mappedData)
	if err != nil {
		provider.logger.Err(err).Msg("aws_secrets_manager_file: Failed to marshal mapped secret data")
		return "", err
	}

	return string(mappedBytes), nil
}
