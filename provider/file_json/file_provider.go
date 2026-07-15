package file_json

import (
	"fmt"
	"os"
	"sync"
	"time"

	sharedprovider "github.com/hasura/hasura-secret-refresh/provider"
	"github.com/hasura/hasura-secret-refresh/template"
	"github.com/hasura/hasura-secret-refresh/transform"
	"github.com/rs/zerolog"
)

type FileJsonProvider struct {
	refreshInterval time.Duration
	inputPath       string
	filePath        string
	template        string
	secretTransform *transform.SecretTransform

	logger zerolog.Logger
	mu     *sync.Mutex
}

func CreateFileJsonProvider(config map[string]interface{}, logger zerolog.Logger) (FileJsonProvider, error) {
	inputPathI, found := config["input_path"]
	if !found {
		logger.Error().Msg("file_json: Config 'input_path' not found")
		return FileJsonProvider{}, fmt.Errorf("required configs not found")
	}
	inputPath, ok := inputPathI.(string)
	if !ok {
		logger.Error().Msg("file_json: 'input_path' must be a string")
		return FileJsonProvider{}, fmt.Errorf("config not valid")
	}

	filePathI, found := config["path"]
	if !found {
		logger.Error().Msg("file_json: Config 'path' not found")
		return FileJsonProvider{}, fmt.Errorf("required configs not found")
	}
	filePath, ok := filePathI.(string)
	if !ok {
		logger.Error().Msg("file_json: 'path' must be a string")
		return FileJsonProvider{}, fmt.Errorf("config not valid")
	}

	refreshIntervalI, found := config["refresh"]
	if !found {
		logger.Error().Msg("file_json: Config 'refresh' not found")
		return FileJsonProvider{}, fmt.Errorf("required configs not found")
	}
	refreshIntervalInt, ok := refreshIntervalI.(int)
	if !ok {
		logger.Error().Msg("file_json: 'refresh' must be an integer")
		return FileJsonProvider{}, fmt.Errorf("config not valid")
	}
	refreshInterval := time.Duration(refreshIntervalInt) * time.Second

	secretTemplate := ""
	secretTemplateI, ok := config["template"]
	if ok {
		secretTemplate, ok = secretTemplateI.(string)
		if !ok {
			logger.Error().Msg("file_json: 'template' must be a string")
			return FileJsonProvider{}, fmt.Errorf("config not valid")
		}
	}

	secretTransform, err := transform.ParseSecretTransformFromConfig(config, logger)
	if err != nil {
		return FileJsonProvider{}, err
	}

	if secretTemplate != "" && secretTransform.HasTransformations() {
		logger.Error().Msg("file_json: Only one of 'template' or 'transform' can be configured, not both")
		return FileJsonProvider{}, fmt.Errorf("config not valid: Only one of 'template' or 'transform' can be configured, not both")
	}

	provider := FileJsonProvider{
		refreshInterval: refreshInterval,
		inputPath:       inputPath,
		filePath:        filePath,
		logger:          logger,
		template:        secretTemplate,
		secretTransform: secretTransform,
		mu:              &sync.Mutex{},
	}

	logger.Info().
		Str("refresh", refreshInterval.String()).
		Str("input_path", inputPath).
		Str("file_path", filePath).
		Int("key_mappings", len(secretTransform.GetMappings())).
		Str("transform_mode", string(secretTransform.GetMode())).
		Msg("Creating file_json provider")

	return provider, nil
}

func (provider FileJsonProvider) Start() {
	err := sharedprovider.WriteSecretFile(provider.filePath, []byte(""))
	if err != nil {
		provider.logger.Err(err).Msgf("file_json: Error occurred while writing to file %s", provider.filePath)
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
		provider.logger.Info().Msgf("file_json: Successfully read secret from %s. Refreshing in %s", provider.inputPath, provider.refreshInterval)
		time.Sleep(provider.refreshInterval)
	}
}

func (provider FileJsonProvider) Refresh() error {
	provider.logger.Info().Msgf("file_json: Refresh invoked for input %s", provider.inputPath)
	secret, err := provider.getSecret()
	if err != nil {
		return err
	}
	err = provider.writeFile(secret)
	if err != nil {
		return err
	}
	provider.logger.Info().Msgf("file_json: Successfully refreshed secret from %s upon invocation", provider.inputPath)
	return nil
}

func (provider FileJsonProvider) FileName() string {
	return provider.filePath
}

func (provider FileJsonProvider) getSecret() (string, error) {
	provider.logger.Info().Msgf("file_json: Reading secret from %s", provider.inputPath)
	data, err := os.ReadFile(provider.inputPath)
	if err != nil {
		provider.logger.Err(err).Msgf("file_json: Error reading input file '%s'", provider.inputPath)
		return "", err
	}

	secretString := string(data)

	// Apply key mapping if configured
	if provider.secretTransform.HasTransformations() {
		secretString, err = provider.secretTransform.Transform(secretString)
		if err != nil {
			provider.logger.Err(err).Msg("file_json: Error applying secret transformation")
			return "", err
		}
	}

	if provider.template != "" {
		templ := template.Template{Templ: provider.template, Logger: provider.logger}
		secretString = templ.Substitute(secretString)
	}

	return secretString, nil
}

func (provider FileJsonProvider) writeFile(secretString string) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	err := sharedprovider.WriteSecretFile(provider.filePath, []byte(secretString))
	if err != nil {
		provider.logger.Err(err).Msgf("file_json: Error occurred while writing to file %s", provider.filePath)
		return err
	}
	return nil
}
