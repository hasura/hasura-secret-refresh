package provider

import "os"

const SecretFileMode os.FileMode = 0o644

// WriteSecretFile writes secret data and enforces a consistent mode even when
// the target file already exists with a more restrictive permission set.
func WriteSecretFile(path string, content []byte) error {
	if err := os.WriteFile(path, content, SecretFileMode); err != nil {
		return err
	}
	return os.Chmod(path, SecretFileMode)
}
