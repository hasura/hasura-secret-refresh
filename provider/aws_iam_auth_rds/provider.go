package aws_iam_auth_rds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/rs/zerolog"
)

type AWSIAMAuthRDS struct {
	Region string `json:"region"`
	DBName string `json:"db_name"`
	DBUser string `json:"db_user"`
	DBHost string `json:"db_host"`
	DBPort int    `json:"db_port"`
}

const (
	ttl    = "ttl"
	region = "region"
)

const (
	defaultTtl = time.Minute * 15
)

var (
	InitError = errors.New("aws_iam_auth: unable to initialize")
)

func Create(inputCfg map[string]interface{}, logger zerolog.Logger) (*AWSIAMAuthRDS, error) {
	c, err := json.Marshal(inputCfg)
	if err != nil {
		return nil, err
	}
	var awsConfig AWSIAMAuthRDS
	err = json.Unmarshal(c, &awsConfig)
	if err != nil {
		return nil, err
	}
	var dbEndpoint string = fmt.Sprintf("%s:%d", awsConfig.DBHost, awsConfig.DBPort)
	fmt.Println(dbEndpoint)

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic("configuration error: " + err.Error())
	}

	authenticationToken, err := auth.BuildAuthToken(
		context.TODO(), dbEndpoint, awsConfig.Region, awsConfig.DBUser, cfg.Credentials)
	if err != nil {
		panic("failed to create authentication token: " + err.Error())
	}

	// dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?tls=true&allowCleartextPasswords=true", awsConfig.DBUser, authenticationToken, dbEndpoint, awsConfig.DBName)
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s",
		awsConfig.DBHost, awsConfig.DBPort, awsConfig.DBUser, authenticationToken, awsConfig.DBName,
	)
	fmt.Printf("DSN: %s", dsn)

	// Do the authentication and get the token
	return &awsConfig, nil
}
