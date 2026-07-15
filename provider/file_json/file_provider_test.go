package file_json

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateFileJsonProvider(t *testing.T) {
	logger := zerolog.New(os.Stderr)

	t.Run("valid config", func(t *testing.T) {
		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": "/source-secrets/secrets.json",
			"path":       "/secrets/output.json",
			"refresh":    60,
		}

		provider, err := CreateFileJsonProvider(config, logger)
		require.NoError(t, err)
		assert.Equal(t, "/source-secrets/secrets.json", provider.inputPath)
		assert.Equal(t, "/secrets/output.json", provider.filePath)
		assert.Equal(t, "/secrets/output.json", provider.FileName())
	})

	t.Run("missing input_path", func(t *testing.T) {
		config := map[string]interface{}{
			"type":    "file_json",
			"path":    "/secrets/output.json",
			"refresh": 60,
		}

		_, err := CreateFileJsonProvider(config, logger)
		assert.Error(t, err)
	})

	t.Run("missing path", func(t *testing.T) {
		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": "/source-secrets/secrets.json",
			"refresh":    60,
		}

		_, err := CreateFileJsonProvider(config, logger)
		assert.Error(t, err)
	})

	t.Run("missing refresh", func(t *testing.T) {
		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": "/source-secrets/secrets.json",
			"path":       "/secrets/output.json",
		}

		_, err := CreateFileJsonProvider(config, logger)
		assert.Error(t, err)
	})

	t.Run("template and transform conflict", func(t *testing.T) {
		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": "/source-secrets/secrets.json",
			"path":       "/secrets/output.json",
			"refresh":    60,
			"template":   "some-template",
			"transform": map[string]interface{}{
				"key_mappings": []interface{}{
					map[string]interface{}{
						"from": "a",
						"to":   "b",
					},
				},
			},
		}

		_, err := CreateFileJsonProvider(config, logger)
		assert.Error(t, err)
	})

	t.Run("rejects same file after path cleaning", func(t *testing.T) {
		tmpDir := t.TempDir()
		inputPath := filepath.Join(tmpDir, "secrets.json")

		err := os.WriteFile(inputPath, []byte(`{"token":"value"}`), 0o644)
		require.NoError(t, err)

		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": filepath.Join(tmpDir, ".", "secrets.json"),
			"path":       filepath.Join(tmpDir, "nested", "..", "secrets.json"),
			"refresh":    60,
		}

		_, err = CreateFileJsonProvider(config, logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'input_path' and 'path' must refer to different files")
	})

	t.Run("rejects same file through symlink resolution", func(t *testing.T) {
		tmpDir := t.TempDir()
		inputPath := filepath.Join(tmpDir, "secrets.json")
		symlinkPath := filepath.Join(tmpDir, "secrets-link.json")

		err := os.WriteFile(inputPath, []byte(`{"token":"value"}`), 0o644)
		require.NoError(t, err)
		if err := os.Symlink(inputPath, symlinkPath); err != nil {
			t.Skipf("unable to create symlink on this platform: %v", err)
		}

		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": symlinkPath,
			"path":       inputPath,
			"refresh":    60,
		}

		_, err = CreateFileJsonProvider(config, logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'input_path' and 'path' must refer to different files")
	})
}

func TestFileJsonProviderRefresh(t *testing.T) {
	logger := zerolog.New(os.Stderr)

	t.Run("reads and writes JSON file without transform", func(t *testing.T) {
		tmpDir := t.TempDir()
		inputPath := filepath.Join(tmpDir, "input.json")
		outputPath := filepath.Join(tmpDir, "output.json")

		inputData := map[string]string{
			"DB_HOST":     "localhost",
			"DB_PASSWORD": "secret123",
		}
		inputBytes, _ := json.Marshal(inputData)
		err := os.WriteFile(inputPath, inputBytes, 0644)
		require.NoError(t, err)

		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": inputPath,
			"path":       outputPath,
			"refresh":    60,
		}

		provider, err := CreateFileJsonProvider(config, logger)
		require.NoError(t, err)

		err = provider.Refresh()
		require.NoError(t, err)

		output, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		var outputData map[string]string
		err = json.Unmarshal(output, &outputData)
		require.NoError(t, err)
		assert.Equal(t, "localhost", outputData["DB_HOST"])
		assert.Equal(t, "secret123", outputData["DB_PASSWORD"])
	})

	t.Run("applies key mapping transform", func(t *testing.T) {
		tmpDir := t.TempDir()
		inputPath := filepath.Join(tmpDir, "input.json")
		outputPath := filepath.Join(tmpDir, "output.json")

		inputData := map[string]string{
			"HASURA_GRAPHQL_ADMIN_SECRET": "admin123",
			"DB_PASSWORD":                 "dbpass",
		}
		inputBytes, _ := json.Marshal(inputData)
		err := os.WriteFile(inputPath, inputBytes, 0644)
		require.NoError(t, err)

		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": inputPath,
			"path":       outputPath,
			"refresh":    60,
			"transform": map[string]interface{}{
				"mode": "transformed_only",
				"key_mappings": []interface{}{
					map[string]interface{}{
						"from": "HASURA_GRAPHQL_ADMIN_SECRET",
						"to":   "ADMIN_SECRET",
					},
					map[string]interface{}{
						"from": "DB_PASSWORD",
						"to":   "POSTGRES_PASSWORD",
					},
				},
			},
		}

		provider, err := CreateFileJsonProvider(config, logger)
		require.NoError(t, err)

		err = provider.Refresh()
		require.NoError(t, err)

		output, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		var outputData map[string]string
		err = json.Unmarshal(output, &outputData)
		require.NoError(t, err)
		assert.Equal(t, "admin123", outputData["ADMIN_SECRET"])
		assert.Equal(t, "dbpass", outputData["POSTGRES_PASSWORD"])
		// transformed_only mode should not include original keys
		_, hasOriginal := outputData["HASURA_GRAPHQL_ADMIN_SECRET"]
		assert.False(t, hasOriginal)
	})

	t.Run("keep_all mode preserves original keys", func(t *testing.T) {
		tmpDir := t.TempDir()
		inputPath := filepath.Join(tmpDir, "input.json")
		outputPath := filepath.Join(tmpDir, "output.json")

		inputData := map[string]string{
			"HASURA_GRAPHQL_ADMIN_SECRET": "admin123",
			"DB_HOST":                     "localhost",
		}
		inputBytes, _ := json.Marshal(inputData)
		err := os.WriteFile(inputPath, inputBytes, 0644)
		require.NoError(t, err)

		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": inputPath,
			"path":       outputPath,
			"refresh":    60,
			"transform": map[string]interface{}{
				"mode": "keep_all",
				"key_mappings": []interface{}{
					map[string]interface{}{
						"from": "HASURA_GRAPHQL_ADMIN_SECRET",
						"to":   "ADMIN_SECRET",
					},
				},
			},
		}

		provider, err := CreateFileJsonProvider(config, logger)
		require.NoError(t, err)

		err = provider.Refresh()
		require.NoError(t, err)

		output, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		var outputData map[string]string
		err = json.Unmarshal(output, &outputData)
		require.NoError(t, err)
		assert.Equal(t, "admin123", outputData["ADMIN_SECRET"])
		assert.Equal(t, "localhost", outputData["DB_HOST"])
		// In keep_all mode, original key is removed when mapped
		_, hasOriginal := outputData["HASURA_GRAPHQL_ADMIN_SECRET"]
		assert.False(t, hasOriginal)
	})

	t.Run("input file not found returns error", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "output.json")

		config := map[string]interface{}{
			"type":       "file_json",
			"input_path": "/nonexistent/input.json",
			"path":       outputPath,
			"refresh":    60,
		}

		provider, err := CreateFileJsonProvider(config, logger)
		require.NoError(t, err)

		err = provider.Refresh()
		assert.Error(t, err)
	})
}
