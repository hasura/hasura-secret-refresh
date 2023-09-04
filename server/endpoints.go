package server

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/hasura/hasura-secret-refresh/provider"
	template "github.com/hasura/hasura-secret-refresh/template"
)

func Serve(config Config) {
	http.Handle("/", &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			inHeaders := make(map[string]string)
			headersToDelete := make([]string, 0, 4)
			for k, _ := range req.In.Header {
				inHeaders[k] = req.In.Header.Get(k)
				if provider.IsRequestConfig(k) {
					headersToDelete = append(headersToDelete, k)
				}
			}
			for _, v := range headersToDelete {
				req.Out.Header.Del(v)
			}
			requestConfig, err := provider.GetRequestConfig(inHeaders)
			if err != nil {
				//TODO: Handle error
			}
			url, err := url.Parse(requestConfig.DestinationUrl)
			if err != nil {
				// TODO: handle error
			}
			req.SetURL(url)
			provider, ok := config.Providers[requestConfig.SecretProvider]
			if !ok {
				//TODO: handle error
			}
			secret, err := provider.GetSecret(requestConfig)
			if err != nil {
				//TODO: handle error
			}
			headerKey, headerVal, err := template.GetHeaderFromTemplate(requestConfig.HeaderTemplate, secret)
			if err != nil {
				//TODO: handle error
			}
			req.Out.Header.Set(headerKey, headerVal)
		},
	})
	http.ListenAndServe(":5353", nil)
}
