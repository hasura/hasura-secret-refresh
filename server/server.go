package server

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/hasura/hasura-secret-refresh/process_secrets"
	"github.com/hasura/hasura-secret-refresh/store"
)

const forwardToHeader string = "X-Hasura-Forward-Host"

func Serve() {
	configPath := parseCliArgs()
	config, err := parseConfig(*configPath)
	if err != nil {
		log.Fatalf("Unable to parse config: %s", err)
	}
	secretsStore, err := store.InitializeSecretStore(config)
	if err != nil {
		log.Fatalf("Unable to initialize secret store: %s", err)
	}

	http.Handle("/", &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			forwardTo := req.In.Header.Get(forwardToHeader)
			url, err := url.Parse(forwardTo)
			if err != nil {
				// TODO: handle error
			}
			req.SetURL(url)
			err = modifyHeaders(req.Out, secretsStore)
			if err != nil {
				// TODO: handle error
			}
		},
	})
	http.ListenAndServe(":5353", nil)
}

func parseCliArgs() (configPath *string) {
	flagName := "config-file"
	defaultPath := "./config.json"
	flagDescription := "path to config file"
	configPath = flag.String(flagName, defaultPath, flagDescription)
	return
}

func parseConfig(configPath string) (config map[string]interface{}, err error) {
	config = make(map[string]interface{})
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		return
	}
	return
}

func modifyHeaders(req *http.Request, secretsStore process_secrets.SecretsStore) (err error) {
	headers := make(map[string]string)
	for k, _ := range req.Header {
		headers[k] = req.Header.Get(k)
	}
	newHeaders, err := process_secrets.GetChangedHeaders(headers, secretsStore)
	if err != nil {
		//TODO: Handle error
	}
	for k, v := range newHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Del(forwardToHeader)
	return
}
