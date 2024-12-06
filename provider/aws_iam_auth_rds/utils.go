package aws_iam_auth_rds

import (
	"fmt"

	"github.com/rs/zerolog"
)

func parseInputConfig(config map[string]interface{}, logger zerolog.Logger) (*AWSIAMAuthRDSFile, error) {
	regionI, found := config["region"]
	if !found {
		logger.Error().Msg("config 'region' not found")
		return nil, fmt.Errorf("required configs not found")
	}
	region, ok := regionI.(string)
	if !ok {
		logger.Error().Msg("'region' must be a string")
		return nil, fmt.Errorf("config not valid")
	}
	filePathI, found := config["path"]
	if !found {
		logger.Error().Msg("config 'path' not found")
		return nil, fmt.Errorf("required configs not found")
	}
	filePath, ok := filePathI.(string)
	if !ok {
		logger.Error().Msg("'path' must be a string")
		return nil, fmt.Errorf("config not valid")
	}
	dbNameI, found := config["db_name"]
	if !found {
		logger.Error().Msg("config 'db_name' not found")
		return nil, fmt.Errorf("required configs not found")
	}
	dbName, ok := dbNameI.(string)
	if !ok {
		logger.Error().Msg("'db_name' must be a string")
		return nil, fmt.Errorf("config not valid")
	}
	dbUserI, found := config["db_user"]
	if !found {
		logger.Error().Msg("config 'db_user' not found")
		return nil, fmt.Errorf("required configs not found")
	}
	dbUser, ok := dbUserI.(string)
	if !ok {
		logger.Error().Msg("'db_user' must be a string")
		return nil, fmt.Errorf("config not valid")
	}
	dbHostI, found := config["db_host"]
	if !found {
		logger.Error().Msg("config 'db_host' not found")
		return nil, fmt.Errorf("required configs not found")
	}
	dbHost, ok := dbHostI.(string)
	if !ok {
		logger.Error().Msg("'db_host' must be a string")
		return nil, fmt.Errorf("config not valid")
	}
	dbPortI, found := config["db_port"]
	if !found {
		logger.Error().Msg("config 'db_port' not found")
		return nil, fmt.Errorf("required configs not found")
	}
	dbPort, ok := dbPortI.(int)
	if !ok {
		logger.Error().Msg("'db_port' must be an int")
		return nil, fmt.Errorf("config not valid")
	}
	return &AWSIAMAuthRDSFile{
		region:   region,
		dbName:   dbName,
		dbUser:   dbUser,
		dbHost:   dbHost,
		dbPort:   dbPort,
		filePath: filePath,
	}, nil
}
