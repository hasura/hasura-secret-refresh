package hashicorp_vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/vault/api"
	authkubernetes "github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/rs/zerolog"
)

const (
	defaultMountPath = "kubernetes"
	defaultJwtPath   = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	authMethodK8s    = "kubernetes"
)

var (
	ErrAuthConfig = errors.New("hashicorp_vault: invalid auth configuration")
	ErrLogin      = errors.New("hashicorp_vault: login failed")
)

// VaultConfig captures the parsed Vault connection and auth configuration.
type VaultConfig struct {
	Address     string
	Namespace   string
	CACert      string
	SkipVerify  bool
	AuthRole    string
	AuthMethod  string
	MountPath   string
	JwtPath     string
}

// parseVaultConfig extracts the common Vault connection / auth options out
// of a provider config map. It does not call Vault — it just validates input.
func parseVaultConfig(config map[string]interface{}) (VaultConfig, error) {
	vc := VaultConfig{
		AuthMethod: authMethodK8s,
		MountPath:  defaultMountPath,
		JwtPath:    defaultJwtPath,
	}

	addrI, found := config["vault_addr"]
	if !found {
		return vc, fmt.Errorf("%w: required config 'vault_addr' not found", ErrAuthConfig)
	}
	addr, ok := addrI.(string)
	if !ok {
		return vc, fmt.Errorf("%w: 'vault_addr' must be a string", ErrAuthConfig)
	}
	vc.Address = addr

	if nsI, ok := config["namespace"]; ok {
		ns, ok := nsI.(string)
		if !ok {
			return vc, fmt.Errorf("%w: 'namespace' must be a string", ErrAuthConfig)
		}
		vc.Namespace = ns
	}

	if tlsI, ok := config["tls"]; ok {
		tlsMap, ok := tlsI.(map[string]interface{})
		if !ok {
			return vc, fmt.Errorf("%w: 'tls' must be a map", ErrAuthConfig)
		}
		if caI, ok := tlsMap["ca_cert"]; ok {
			ca, ok := caI.(string)
			if !ok {
				return vc, fmt.Errorf("%w: 'tls.ca_cert' must be a string", ErrAuthConfig)
			}
			vc.CACert = ca
		}
		if skipI, ok := tlsMap["skip_verify"]; ok {
			skip, ok := skipI.(bool)
			if !ok {
				return vc, fmt.Errorf("%w: 'tls.skip_verify' must be a bool", ErrAuthConfig)
			}
			vc.SkipVerify = skip
		}
	}

	authI, found := config["auth"]
	if !found {
		return vc, fmt.Errorf("%w: required config 'auth' not found", ErrAuthConfig)
	}
	authMap, ok := authI.(map[string]interface{})
	if !ok {
		return vc, fmt.Errorf("%w: 'auth' must be a map", ErrAuthConfig)
	}

	if methodI, ok := authMap["method"]; ok {
		method, ok := methodI.(string)
		if !ok {
			return vc, fmt.Errorf("%w: 'auth.method' must be a string", ErrAuthConfig)
		}
		if method != authMethodK8s {
			return vc, fmt.Errorf("%w: only auth method '%s' is supported, got '%s'", ErrAuthConfig, authMethodK8s, method)
		}
		vc.AuthMethod = method
	}

	roleI, found := authMap["role"]
	if !found {
		return vc, fmt.Errorf("%w: required config 'auth.role' not found", ErrAuthConfig)
	}
	role, ok := roleI.(string)
	if !ok {
		return vc, fmt.Errorf("%w: 'auth.role' must be a string", ErrAuthConfig)
	}
	vc.AuthRole = role

	if mpI, ok := authMap["mount_path"]; ok {
		mp, ok := mpI.(string)
		if !ok {
			return vc, fmt.Errorf("%w: 'auth.mount_path' must be a string", ErrAuthConfig)
		}
		if mp != "" {
			vc.MountPath = mp
		}
	}

	if jwtI, ok := authMap["jwt_path"]; ok {
		jp, ok := jwtI.(string)
		if !ok {
			return vc, fmt.Errorf("%w: 'auth.jwt_path' must be a string", ErrAuthConfig)
		}
		if jp != "" {
			vc.JwtPath = jp
		}
	}

	return vc, nil
}

// newVaultClient builds an *api.Client wired with TLS + namespace, but
// does not perform a login.
func newVaultClient(vc VaultConfig) (*api.Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = vc.Address
	cfg.Timeout = 30 * time.Second

	if vc.CACert != "" || vc.SkipVerify {
		tlsCfg := &api.TLSConfig{
			CACert:     vc.CACert,
			Insecure:   vc.SkipVerify,
		}
		if err := cfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("hashicorp_vault: failed to configure TLS: %w", err)
		}
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("hashicorp_vault: failed to construct client: %w", err)
	}

	if vc.Namespace != "" {
		client.SetNamespace(vc.Namespace)
	}

	return client, nil
}

// login performs a Kubernetes-auth login against Vault and returns the
// resulting Secret (which carries the renewable client token).
func login(ctx context.Context, client *api.Client, vc VaultConfig, logger zerolog.Logger) (*api.Secret, error) {
	if _, err := os.Stat(vc.JwtPath); err != nil {
		return nil, fmt.Errorf("%w: service account token file not accessible at %s: %v", ErrLogin, vc.JwtPath, err)
	}

	k8sAuth, err := authkubernetes.NewKubernetesAuth(
		vc.AuthRole,
		authkubernetes.WithServiceAccountTokenPath(vc.JwtPath),
		authkubernetes.WithMountPath(vc.MountPath),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLogin, err)
	}

	authInfo, err := client.Auth().Login(ctx, k8sAuth)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLogin, err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("%w: no auth info returned", ErrLogin)
	}

	logger.Info().
		Str("role", vc.AuthRole).
		Str("mount_path", vc.MountPath).
		Bool("renewable", authInfo.Auth != nil && authInfo.Auth.Renewable).
		Msg("hashicorp_vault: kubernetes auth login successful")

	return authInfo, nil
}
