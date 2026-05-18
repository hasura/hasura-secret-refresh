package hashicorp_vault

import (
	"fmt"
	"sync"
	"time"

	sharedprovider "github.com/hasura/hasura-secret-refresh/provider"
	"github.com/hasura/hasura-secret-refresh/template"
	"github.com/hasura/hasura-secret-refresh/transform"
	"github.com/rs/zerolog"
)

type HashicorpVaultFile struct {
	refreshInterval time.Duration
	client          *vaultClient
	filePath        string
	mount           string
	path            string
	version         string
	field           string
	template        string
	secretTransform *transform.SecretTransform
	logger          zerolog.Logger
	mu              *sync.Mutex
}

// CreateHashicorpVaultFile builds the file provider variant. It eagerly
// authenticates against Vault so misconfiguration surfaces at boot.
func CreateHashicorpVaultFile(config map[string]interface{}, logger zerolog.Logger) (HashicorpVaultFile, error) {
	vc, err := parseVaultConfig(config)
	if err != nil {
		logger.Err(err).Msg("hashicorp_vault_file: invalid vault/auth config")
		return HashicorpVaultFile{}, fmt.Errorf("config not valid: %v", err)
	}

	filePathI, found := config["path_on_disk"]
	if !found {
		logger.Error().Msg("hashicorp_vault_file: Config 'path_on_disk' not found")
		return HashicorpVaultFile{}, fmt.Errorf("required configs not found")
	}
	filePath, ok := filePathI.(string)
	if !ok {
		logger.Error().Msg("hashicorp_vault_file: 'path_on_disk' must be a string")
		return HashicorpVaultFile{}, fmt.Errorf("config not valid")
	}

	pathI, found := config["path"]
	if !found {
		logger.Error().Msg("hashicorp_vault_file: Config 'path' not found")
		return HashicorpVaultFile{}, fmt.Errorf("required configs not found")
	}
	path, ok := pathI.(string)
	if !ok {
		logger.Error().Msg("hashicorp_vault_file: 'path' must be a string")
		return HashicorpVaultFile{}, fmt.Errorf("config not valid")
	}

	mount := defaultMount
	if mountI, ok := config["mount"]; ok {
		m, ok := mountI.(string)
		if !ok {
			logger.Error().Msg("hashicorp_vault_file: 'mount' must be a string")
			return HashicorpVaultFile{}, fmt.Errorf("config not valid")
		}
		if m != "" {
			mount = m
		}
	}

	refreshI, found := config["refresh"]
	if !found {
		logger.Error().Msg("hashicorp_vault_file: Config 'refresh' not found")
		return HashicorpVaultFile{}, fmt.Errorf("required configs not found")
	}
	refreshInt, ok := refreshI.(int)
	if !ok {
		logger.Error().Msg("hashicorp_vault_file: 'refresh' must be an integer")
		return HashicorpVaultFile{}, fmt.Errorf("config not valid")
	}
	refreshInterval := time.Duration(refreshInt) * time.Second

	version := ""
	if versionI, ok := config["version"]; ok {
		switch v := versionI.(type) {
		case string:
			version = v
		case int:
			version = fmt.Sprintf("%d", v)
		default:
			logger.Error().Msg("hashicorp_vault_file: 'version' must be a string or integer")
			return HashicorpVaultFile{}, fmt.Errorf("config not valid")
		}
	}

	field := ""
	if fieldI, ok := config["field"]; ok {
		field, ok = fieldI.(string)
		if !ok {
			logger.Error().Msg("hashicorp_vault_file: 'field' must be a string")
			return HashicorpVaultFile{}, fmt.Errorf("config not valid")
		}
	}

	secretTemplate := ""
	if templateI, ok := config["template"]; ok {
		secretTemplate, ok = templateI.(string)
		if !ok {
			logger.Error().Msg("hashicorp_vault_file: 'template' must be a string")
			return HashicorpVaultFile{}, fmt.Errorf("config not valid")
		}
	}

	secretTransform, err := transform.ParseSecretTransformFromConfig(config, logger)
	if err != nil {
		return HashicorpVaultFile{}, err
	}

	if secretTemplate != "" && secretTransform.HasTransformations() {
		logger.Error().Msg("hashicorp_vault_file: Only one of 'template' or 'transform' can be configured, not both")
		return HashicorpVaultFile{}, fmt.Errorf("config not valid: Only one of 'template' or 'transform' can be configured, not both")
	}

	client, err := newAuthenticatedClient(vc, logger)
	if err != nil {
		return HashicorpVaultFile{}, err
	}

	hv := HashicorpVaultFile{
		refreshInterval: refreshInterval,
		client:          client,
		filePath:        filePath,
		mount:           mount,
		path:            path,
		version:         version,
		field:           field,
		template:        secretTemplate,
		secretTransform: secretTransform,
		logger:          logger,
		mu:              &sync.Mutex{},
	}

	logger.Info().
		Str("refresh", refreshInterval.String()).
		Str("file_path", filePath).
		Str("vault_addr", vc.Address).
		Str("mount", mount).
		Str("path", path).
		Int("transformations", len(secretTransform.GetMappings())).
		Str("transform_mode", string(secretTransform.GetMode())).
		Msg("Creating HashiCorp Vault file provider")

	return hv, nil
}

func (p HashicorpVaultFile) Start() {
	if err := sharedprovider.WriteSecretFile(p.filePath, []byte("")); err != nil {
		p.logger.Err(err).Msgf("hashicorp_vault_file: Error occurred while writing to file %s", p.filePath)
	}
	for {
		secret, err := p.getSecret()
		if err != nil {
			time.Sleep(p.refreshInterval)
			continue
		}
		if err := p.writeFile(secret); err != nil {
			time.Sleep(p.refreshInterval)
			continue
		}
		p.logger.Info().Msgf("hashicorp_vault_file: Successfully fetched secret %s. Fetching again in %s", p.path, p.refreshInterval)
		time.Sleep(p.refreshInterval)
	}
}

func (p HashicorpVaultFile) Refresh() error {
	p.logger.Info().Msgf("hashicorp_vault_file: Refresh invoked for secret %s", p.path)
	secret, err := p.getSecret()
	if err != nil {
		return err
	}
	if err := p.writeFile(secret); err != nil {
		return err
	}
	p.logger.Info().Msgf("hashicorp_vault_file: Successfully refreshed secret %s upon invocation", p.path)
	return nil
}

func (p HashicorpVaultFile) FileName() string {
	return p.filePath
}

func (p HashicorpVaultFile) getSecret() (string, error) {
	p.logger.Info().Msgf("hashicorp_vault_file: Fetching secret %s", p.path)

	data, err := readKVv2WithTimeout(p.client.client(), p.mount, p.path, p.version, p.logger)
	if err != nil {
		p.logger.Err(err).Msgf("hashicorp_vault_file: Error retrieving secret '%s' from Vault", p.path)
		return "", err
	}

	secretString, err := extractField(data, p.field)
	if err != nil {
		p.logger.Err(err).Msgf("hashicorp_vault_file: Error extracting field from secret '%s'", p.path)
		return "", err
	}

	if p.secretTransform.HasTransformations() {
		secretString, err = p.secretTransform.Transform(secretString)
		if err != nil {
			p.logger.Err(err).Msg("hashicorp_vault_file: Error applying secret transformation")
			return "", err
		}
	}
	if p.template != "" {
		templ := template.Template{Templ: p.template, Logger: p.logger}
		secretString = templ.Substitute(secretString)
	}
	return secretString, nil
}

func (p HashicorpVaultFile) writeFile(secretString string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := sharedprovider.WriteSecretFile(p.filePath, []byte(secretString)); err != nil {
		p.logger.Err(err).Msgf("hashicorp_vault_file: Error writing secret %s to file %s", p.path, p.filePath)
		return err
	}
	p.logger.Info().Msgf("hashicorp_vault_file: Successfully wrote secret %s to file %s", p.path, p.filePath)
	return nil
}
