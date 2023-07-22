package server

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/hasura/hasura-secret-refresh/process_secrets"
	"github.com/hasura/hasura-secret-refresh/store"
)

func Serve() {
	secretsStore, err := store.InitializeSecretStore(map[string]interface{}{
		"cache_ttl": 300,
	})
	if err != nil {
		//TODO: Handle error
	}

	rewrite := func(req *httputil.ProxyRequest) {
		headers := make(map[string]string)
		for k, _ := range req.In.Header {
			headers[k] = req.In.Header.Get(k)
		}
		newHeaders, err := process_secrets.GetChangedHeaders(headers, secretsStore)
		forwardToHeader := "X-Hasura-Forward-Host"
		forwardTo := req.In.Header.Get(forwardToHeader)
		url, err := url.Parse(forwardTo)
		if err != nil {
			// TODO: handle error
		}
		for k, v := range newHeaders {
			req.Out.Header.Set(k, v)
		}
		req.Out.Header.Del(forwardToHeader)
		req.SetURL(url)
	}

	// https://pkg.go.dev/net/http/httputil#ReverseProxy
	http.Handle("/", &httputil.ReverseProxy{
		Rewrite: rewrite,
	})
	http.ListenAndServe(":5353", nil)
}
