package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/hasura/hasura-secret-refresh/provider"
)

type RefreshConfig struct {
	// mapping from filepath to provider
	Configs map[string]provider.FileProvider
}

func (c RefreshConfig) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	body := make(map[string]string)
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	fileName, found := body["filename"]
	if !found {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	for f, p := range c.Configs {
		if filepath.ToSlash(f) != filepath.ToSlash(fileName) {
			continue
		}
		err = p.Refresh()
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}
