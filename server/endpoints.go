package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/hasura/hasura-secret-refresh/provider"
	template "github.com/hasura/hasura-secret-refresh/template"
	"github.com/rs/zerolog"
)

func Serve(config Config, logger zerolog.Logger) {
	http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		requestLogger := logger.With().Ctx(r.Context()).
			Str("request_url", r.URL.String()).
			Str("request_method", r.Method).
			Logger()
		inHeaders := make(map[string]string)
		headersToDelete := make([]string, 0, 4)
		for k, _ := range r.Header {
			inHeaders[k] = r.Header.Get(k)
			if provider.IsRequestConfig(k) {
				headersToDelete = append(headersToDelete, k)
			}
		}

		requestConfig, err := provider.GetRequestConfig(inHeaders)
		if err != nil {
			requestLogger.Error().Err(err).Msgf(err.Error())
			http.Error(rw, makeHasuraError(err.Error()), http.StatusBadRequest)
			return
		}

		url, err := getUrl(requestConfig.DestinationUrl)
		if err != nil {
			requestLogger.Error().Msgf(err.Error())
			http.Error(rw, makeHasuraError(err.Error()), http.StatusBadRequest)
			return
		}

		provider_, ok := config.Providers[requestConfig.SecretProvider]
		if !ok {
			errMsg := fmt.Sprintf("Provider name %s sent in header %s does not exist", requestConfig.SecretProvider, provider.SecretProviderHeader)
			requestLogger.Error().Msgf(errMsg)
			http.Error(rw, makeHasuraError(errMsg), http.StatusBadRequest)
			return
		}

		secret, err := provider_.GetSecret(requestConfig)
		if err != nil {
			errMsg := fmt.Sprintf("Unable to fetch secret %s sent in header %s", requestConfig.SecretId, provider.SecretIdHeader)
			requestLogger.Error().Err(err).Msgf(errMsg)
			http.Error(rw, makeHasuraError(errMsg), http.StatusBadRequest)
			return
		}

		headerKey, headerVal, err := template.GetHeaderFromTemplate(requestConfig.HeaderTemplate, secret)
		if err != nil {
			errMsg := fmt.Sprintf("Header template %s sent in header %s is not valid", requestConfig.HeaderTemplate, provider.TemplateHeader)
			requestLogger.Error().Err(err).Msgf(errMsg)
			http.Error(rw, makeHasuraError(errMsg), http.StatusBadRequest)
			return
		}

		reverseProxy := httputil.ReverseProxy{
			Rewrite: func(req *httputil.ProxyRequest) {
				for _, v := range headersToDelete {
					req.Out.Header.Del(v)
				}
				req.SetURL(url)

				req.Out.Header.Set(headerKey, headerVal)
			},
		}
		reverseProxy.ServeHTTP(rw, r)
	})
	http.ListenAndServe(":5353", nil)
}

func makeHasuraError(errorMsg string) string {
	jsonMap := map[string]interface{}{
		"message": errorMsg,
		"extensions": map[string]string{
			"code": "hasura-error",
		},
	}
	json, _ := json.Marshal(jsonMap)
	return string(json)
}

func getUrl(urlStr string) (parsedUrl *url.URL, err error) {
	url_, err := url.Parse(urlStr)
	if err != nil || (url_.Scheme != "http" && url_.Scheme != "https") || url_.Host == "" {
		errMsg := fmt.Sprintf("Unable to parse URL provided in the %s header.", provider.ForwardToHeader)
		return parsedUrl, errors.New(errMsg)
	}
	parsedUrl = &url.URL{
		Scheme: url_.Scheme,
		Host:   url_.Host,
	}
	return
}
