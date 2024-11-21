package aws_iam_auth_rds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/rs/zerolog"
)

type AWSIAMAuthRDSFile struct {
	Region          string `json:"region"`
	DBName          string `json:"db_name"`
	DBUser          string `json:"db_user"`
	DBHost          string `json:"db_host"`
	DBPort          int    `json:"db_port"`
	FilePath        string `json:"path"`
	mu              *sync.Mutex
	refreshInterval time.Duration `json:"refresh"`
	logger          zerolog.Logger
}

const (
	region = "region"
)

const (
	defaultTtl = time.Minute * 15
)

var (
	InitError = errors.New("aws_iam_auth: unable to initialize")
)

func New(inputCfg map[string]interface{}, logger zerolog.Logger) (*AWSIAMAuthRDSFile, error) {
	c, err := json.Marshal(inputCfg)
	if err != nil {
		return nil, err
	}
	var provider AWSIAMAuthRDSFile
	err = json.Unmarshal(c, &provider)
	if err != nil {
		return nil, err
	}
	provider.refreshInterval = time.Duration(300) * time.Second
	provider.mu = &sync.Mutex{}
	return &provider, nil
}

func (provider *AWSIAMAuthRDSFile) Start() {
	err := os.WriteFile(provider.FilePath, []byte(""), 0777)
	if err != nil {
		provider.logger.Err(err).Msgf("aws_iam_auth_rds_file: Error occured while writing to a file :%s", provider.FilePath)
	}
	for {
		authenticationToken, err := provider.getSecret()
		if err != nil {
			// this should succeed ideally, and if that fails we need to act
			time.Sleep(provider.refreshInterval)
			continue
		}
		err = provider.writeFile(authenticationToken)

		if err != nil {
			// todo: handle
			time.Sleep(provider.refreshInterval)
			continue
		}
		provider.logger.Info().Msgf("aws_iam_auth_rds_file: Successfully fetched IAM Token. Fetching again in %s", provider.refreshInterval)
		// dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?tls=true&allowCleartextPasswords=true", provider.DBUser, authenticationToken, dbEndpoint, provider.DBName)
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s",
			provider.DBHost, provider.DBPort, provider.DBUser, authenticationToken, provider.DBName,
		)
		fmt.Println(dsn)
		time.Sleep(provider.refreshInterval)
	}
}

func (provider AWSIAMAuthRDSFile) getSecret() (string, error) {
	var dbEndpoint string = fmt.Sprintf("%s:%d", provider.DBHost, provider.DBPort)
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		provider.logger.Err(err).Msgf("aws_iam_auth_rds_file: auth configuration error :%s", err.Error())
		return "", err
		// panic("configuration error: " + err.Error())
	}

	authenticationToken, err := auth.BuildAuthToken(
		context.TODO(),
		dbEndpoint,
		provider.Region,
		provider.DBUser,
		cfg.Credentials,
	)
	if err != nil {
		provider.logger.Err(err).Msgf("aws_iam_auth_rds_file: error creating token :%s", err.Error())
		return "", err
	}
	return authenticationToken, err
}

func (provider AWSIAMAuthRDSFile) writeFile(secretString string) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	err := os.WriteFile(provider.FilePath, []byte(secretString), 0777)
	if err != nil {
		provider.logger.Err(err).Msgf("aws_secrets_manager_file: Error occurred while writing secret to file %s", provider.FilePath)
		return err
	}
	return nil
}

func (provider AWSIAMAuthRDSFile) FileName() string {
	return provider.FilePath
}

func (provider AWSIAMAuthRDSFile) Refresh() error {
	authenticationToken, err := provider.getSecret()
	if err != nil {
		// this should succeed ideally, and if that fails we need to act
		return err
	}
	err = provider.writeFile(authenticationToken)

	if err != nil {
		// todo: handle
		return err
	}
	provider.logger.Info().Msgf("aws_iam_auth_rds_file: Successfully fetched IAM Token. Fetching again in %s", provider.refreshInterval)
	return nil
}
