package provider

import "os"

const SecretFileMode os.FileMode = 0o644

// WriteSecretFile normalizes the file mode after every write so file-backed
// secrets stay readable by sibling containers even when the file already
// exists or the process umask is restrictive.
func WriteSecretFile(path string, contents []byte) error {
	if err := os.WriteFile(path, contents, SecretFileMode); err != nil {
		return err
	}

	return os.Chmod(path, SecretFileMode)
}
