package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

type RefreshConfig struct {
	// mapping from filepath to provider
	Configs map[string]provider.FileProvider
	Logger  zerolog.Logger
}

func (c RefreshConfig) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	c.Logger.Info().Msgf("Refresh request received")
	if r.Method != http.MethodPost {
		c.Logger.Error().Msgf("Refresh endpoint only accepts 'POST' requests. Received '%s'", r.Method)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	body := make(map[string]string)
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		c.Logger.Err(err).Msgf("Unable to decode refresh request body as JSON")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	fileName, found := body["filename"]
	if !found {
		c.Logger.Error().Msgf("field 'filename' not found in refresh request body")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	c.Logger.Info().Msgf("Refreshing all providers for file %q", fileName)
	count := 0
	for f, p := range c.Configs {
		if filepath.ToSlash(f) != filepath.ToSlash(fileName) {
			continue
		}
		err = p.Refresh()
		if err != nil {
			c.Logger.Error().Msgf("Refreshing failed")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		count += 1
	}
	c.Logger.Info().Msgf("Refreshed %d providers", count)
}
