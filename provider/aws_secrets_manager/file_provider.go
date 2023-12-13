package aws_secrets_manager

import (
	"fmt"
	"os"
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
	logger          zerolog.Logger
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
	awsSm := AwsSecretsManagerFile{
		refreshInterval: refreshInterval,
		filePath:        filePath,
		secretsManager:  smClient,
		secretId:        secretId,
		logger:          logger,
		template:        secretTemplate,
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
		provider.logger.Info().Msgf("aws_secrets_manager_file: Fetching secret %s", provider.secretId)
		res, err := provider.secretsManager.GetSecretValue(
			&secretsmanager.GetSecretValueInput{
				SecretId: &provider.secretId,
			},
		)
		if err != nil {
			provider.logger.Err(err).Msgf("aws_secrets_manager_file: Error occurred while retrieving secret '%s' from aws secrets manager", provider.secretId)
		} else {
			secretString := *res.SecretString
			if provider.template != "" {
				templ := template.Template{Templ: provider.template, Logger: provider.logger}
				secretString = templ.Substitute(secretString)
			}
			err = os.WriteFile(provider.filePath, []byte(secretString), 0777)
			if err != nil {
				provider.logger.Err(err).Msgf("aws_secrets_manager_file: Error occurred while writing secret %s to file %s", provider.secretId, provider.filePath)
			}
			provider.logger.Info().Msgf("aws_secrets_manager_file: Successfully fetched secret %s. Fetching again in %s", provider.secretId, provider.refreshInterval)
		}
		time.Sleep(provider.refreshInterval)
	}
}
