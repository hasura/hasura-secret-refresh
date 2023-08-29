package server

func IsDefaultPath(configPath *string) bool {
	if *configPath == ConfigFileDefaultPath {
		return true
	}
	return false
}
