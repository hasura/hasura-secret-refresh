package hashicorp_vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
)

var (
	ErrSecretNotFound = errors.New("hashicorp_vault: secret not found")
	ErrInvalidKvData  = errors.New("hashicorp_vault: invalid KV v2 response payload")
)

// readKVv2 reads a path from a KV v2 secrets engine and returns the inner
// data map (i.e. the user-facing key/value pairs). It transparently inserts
// the required `/data/` segment into the path.
//
// path should be the user-facing path *without* the `data/` prefix
// (e.g. "postgres/prod"). mount is the KV mount (default "secret").
// version is optional ("" or "0" means "latest").
func readKVv2(ctx context.Context, client *api.Client, mount, path, version string, logger zerolog.Logger) (map[string]interface{}, error) {
	fullPath := buildKVv2Path(mount, path)

	logger.Debug().Str("vault_path", fullPath).Str("version", version).Msg("hashicorp_vault: reading KV v2 secret")

	var (
		secret *api.Secret
		err    error
	)
	if version != "" && version != "0" {
		secret, err = client.Logical().ReadWithDataWithContext(ctx, fullPath, map[string][]string{
			"version": {version},
		})
	} else {
		secret, err = client.Logical().ReadWithContext(ctx, fullPath)
	}
	if err != nil {
		return nil, fmt.Errorf("hashicorp_vault: failed to read '%s': %w", fullPath, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, fullPath)
	}

	// KV v2 wraps the user payload under data.data.
	dataI, ok := secret.Data["data"]
	if !ok {
		return nil, fmt.Errorf("%w: missing 'data' key in response from %s", ErrInvalidKvData, fullPath)
	}
	data, ok := dataI.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: 'data' is not an object in response from %s", ErrInvalidKvData, fullPath)
	}

	return data, nil
}

// readKVv2WithTimeout is a convenience that wraps readKVv2 with a context
// timeout of 30s.
func readKVv2WithTimeout(client *api.Client, mount, path, version string, logger zerolog.Logger) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return readKVv2(ctx, client, mount, path, version, logger)
}

// buildKVv2Path constructs the canonical KV v2 read path
// "<mount>/data/<path>" while tolerating callers who already included a
// leading "data/" or extra slashes.
func buildKVv2Path(mount, path string) string {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		mount = "secret"
	}
	path = strings.TrimLeft(path, "/")
	// If caller already gave us a path like "data/foo/bar", honor it.
	if strings.HasPrefix(path, "data/") {
		return mount + "/" + path
	}
	return mount + "/data/" + path
}

// extractField pulls a single string-valued field out of a KV v2 data map.
// If field is empty, the entire map is JSON-encoded and returned as a
// string instead.
func extractField(data map[string]interface{}, field string) (string, error) {
	if field == "" {
		b, err := json.Marshal(data)
		if err != nil {
			return "", fmt.Errorf("hashicorp_vault: failed to marshal secret data: %w", err)
		}
		return string(b), nil
	}
	v, ok := data[field]
	if !ok {
		return "", fmt.Errorf("hashicorp_vault: field '%s' not found in secret", field)
	}
	switch typed := v.(type) {
	case string:
		return typed, nil
	default:
		b, err := json.Marshal(typed)
		if err != nil {
			return "", fmt.Errorf("hashicorp_vault: failed to marshal field '%s': %w", field, err)
		}
		return string(b), nil
	}
}
