package server

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/hasura/hasura-secret-refresh/store"
	"github.com/hasura/hasura-secret-refresh/store/aws_secrets_manager"
	secretsTemplate "github.com/hasura/hasura-secret-refresh/template"
)

const forwardToHeader string = "X-Hasura-Forward-Host"

func Serve(config Config) {
	awsSecretsManagerConfig := config.Providers[0].(AwsSecretStoreConfig)
	secretsStore, err := aws_secrets_manager.CreateAwsSecretsManagerStore(awsSecretsManagerConfig.CacheTtl)
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

func modifyHeaders(req *http.Request, secretsStore store.SecretsStore) (err error) {
	templates := make(map[secretsTemplate.TemplateKey]secretsTemplate.Template)
	for k, _ := range req.Header {
		templates[secretsTemplate.TemplateKey(k)] = secretsTemplate.Template(req.Header.Get(k))
	}
	requiredKeys := secretsTemplate.GetUniqueKeysFromTemplates(templates)
	result, err := secretsStore.FetchSecrets(requiredKeys)
	if err != nil {
		//TODO: Handle error
	}
	newHeaders := secretsTemplate.ApplyTemplates(templates, result)
	for k, v := range newHeaders {
		req.Header.Set(string(k), v)
	}
	req.Header.Del(forwardToHeader)
	return
}
