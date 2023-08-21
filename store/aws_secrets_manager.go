package store

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"log"
)

type awsSecretsManager struct {
	cache *secretcache.Cache
}

func (store awsSecretsManager) FetchSecrets(keys []string) (secrets map[string]string, err error) {
	secrets = make(map[string]string)
	for _, secretId := range keys {
		var secret string
		secret, err = store.cache.GetSecretString(secretId)
		if err != nil {
			//TODO: handle error
		}
		secrets[secretId] = secret
	}
	return
}

func FetchCertificate() {
	secretName := "jpmc-test-certificate"

	config, err := awsConfig.LoadDefaultConfig(context.TODO(), awsConfig.WithRegion("us-west-2"))
	if err != nil {
		log.Fatal(err)
	}

	// Create Secrets Manager client
	svc := secretsmanager.NewFromConfig(config)

	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(context.TODO(), input)
	if err != nil {
		// For a list of exceptions thrown, see
		// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
		log.Fatal(err.Error())
	}

	// Decrypts secret using the associated KMS key.
	var secretString string = *result.SecretString

	// Your code goes here.

	fmt.Println(secretString)
}

func createAwsSecretsManagerStore(config config) (store awsSecretsManager, err error) {
	secretsCache, err := secretcache.New(
		func(c *secretcache.Cache) { c.CacheConfig.CacheItemTTL = config.CacheTtl.Nanoseconds() },
	)
	if err != nil {
		return
	}
	return awsSecretsManager{cache: secretsCache}, nil
}

//AKIAXWKCGTSOE4OEK7XD
//
//FoiDcBNTTaOGB1FRkgWpk78c6z06D+jbYBt5hIVf
