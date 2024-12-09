package aws_iam_auth_rds

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
)

type AWSIAMAuthRDSFile struct {
	region          string
	dbName          string
	dbUser          string
	dbHost          string
	dbPort          int
	filePath        string
	mu              *sync.Mutex
	refreshInterval time.Duration
	logger          zerolog.Logger
}

func New(config map[string]interface{}, logger zerolog.Logger) (*AWSIAMAuthRDSFile, error) {
	provider, err := parseInputConfig(config, logger)

	if err != nil {
		return nil, err
	}

	// Automatically refresh every 5 minutes
	refreshInterval := time.Duration(300) * time.Second
	provider.refreshInterval = refreshInterval
	provider.logger = logger
	provider.mu = &sync.Mutex{}
	return provider, nil
}

func (provider *AWSIAMAuthRDSFile) buildDSN(authenticationToken string) string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s",
		provider.dbHost, provider.dbPort, provider.dbUser, authenticationToken, provider.dbName,
	)
}

func (provider *AWSIAMAuthRDSFile) checkDSNConnectivity(dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}

	// check if the token generated can indeed be used to connect
	err = db.Ping()
	if err != nil {
		provider.logger.Error().Err(err).Msg("failed to ping the database with the generated token")
		return err
	}
	return nil
}

func (provider *AWSIAMAuthRDSFile) Start() {
	err := os.WriteFile(provider.filePath, []byte(""), 0777)
	if err != nil {
		provider.logger.Err(err).Msgf("error occured while writing to a file :%s", provider.filePath)
	}
	for {
		authenticationToken, err := provider.getSecret()
		if err != nil {
			time.Sleep(provider.refreshInterval)
			continue
		}

		err = provider.checkDSNConnectivity(provider.buildDSN(authenticationToken))
		if err != nil {
			provider.logger.Error().Err(err).Msg("failed to connect to generated token")
			time.Sleep(provider.refreshInterval)
			continue
		}

		err = provider.writeFile(authenticationToken)

		if err != nil {
			// if there was a problem with writing, add a logline
			provider.logger.Error().Err(err).Msg("failed to write token to a file. Retrying ...")
			time.Sleep(provider.refreshInterval)
			continue
		}
		provider.logger.Info().Msgf("successfully fetched IAM Token and written to the file. Fetching again in %s", provider.refreshInterval)
		time.Sleep(provider.refreshInterval)
	}
}

func (provider AWSIAMAuthRDSFile) getSecret() (string, error) {
	var dbEndpoint string = fmt.Sprintf("%s:%d", provider.dbHost, provider.dbPort)
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		provider.logger.Err(err).Msgf("auth configuration error :%s", err.Error())
		return "", err
	}

	authenticationToken, err := auth.BuildAuthToken(
		context.Background(),
		dbEndpoint,
		provider.region,
		provider.dbUser,
		cfg.Credentials,
	)
	if err != nil {
		provider.logger.Err(err).Msgf("error creating token :%s", err.Error())
		return "", err
	}

	return authenticationToken, err
}

func (provider AWSIAMAuthRDSFile) writeFile(secretString string) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	err := os.WriteFile(provider.filePath, []byte(secretString), 0777)
	if err != nil {
		provider.logger.Err(err).Msgf("error occurred while writing secret to file %s", provider.filePath)
		return err
	}
	return nil
}

func (provider AWSIAMAuthRDSFile) FileName() string {
	return provider.filePath
}

func (provider AWSIAMAuthRDSFile) Refresh() error {
	authenticationToken, err := provider.getSecret()
	if err != nil {
		provider.logger.Err(err).Msgf("error occurred while refreshing the secret")
		return err
	}
	err = provider.checkDSNConnectivity(provider.buildDSN(authenticationToken))
	if err != nil {
		provider.logger.Error().Err(err).Msg("failed to connect to generated token")
		return err
	}
	err = provider.writeFile(authenticationToken)

	if err != nil {
		provider.logger.Err(err).Msgf("error occurred while writing the secret to the path: %s", provider.filePath)
		return err
	}
	provider.logger.Info().Msgf("successfully fetched IAM Token. Fetching again in %s", provider.refreshInterval)
	return nil
}
