package server

import (
	"log"
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
				//TODO: return error code
				log.Printf("Unable to get required configuration from request: %s", err)
			}
			url, err := url.Parse(requestConfig.DestinationUrl)
			if err != nil {
				//TODO: return error code
				log.Printf("Unable to parse url %s: %s", requestConfig.DestinationUrl, err)
			}
			req.SetURL(url)
			provider, ok := config.Providers[requestConfig.SecretProvider]
			if !ok {
				//TODO: return error code
				log.Printf("Provider with name %s does not exist", requestConfig.SecretProvider)
			}
			secret, err := provider.GetSecret(requestConfig)
			if err != nil {
				//TODO: return error code
				log.Printf("Unable to get secret: %s", err)
			}
			headerKey, headerVal, err := template.GetHeaderFromTemplate(requestConfig.HeaderTemplate, secret)
			if err != nil {
				//TODO: return error code
				log.Printf("Unable to process header template: %s", err)
			}
			req.Out.Header.Set(headerKey, headerVal)
		},
	})
	http.ListenAndServe(":5353", nil)
}
