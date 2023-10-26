package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

const (
	forwardToHeader      = "X-Hasura-Forward-To"
	secretProviderHeader = "X-Hasura-Secret-Provider"
	templateHeader       = "X-Hasura-Secret-Header"
)

type requestConf struct {
	destinationUrl string
	secretProvider string
	headerTemplate string
}

func getRequestRewriteDetails(
	rw http.ResponseWriter, r *http.Request, providers map[string]provider.HttpProvider, requestLogger zerolog.Logger,
) (
	url *url.URL, headerKey string, headerVal string, providerDeleteConfigHeader func(*http.Header), ok bool,
) {
	providerDeleteConfigHeader = func(*http.Header) {}
	requestConfig, ok := getRequestConfig(rw, r, requestLogger)
	if !ok {
		return
	}
	url, ok = parseDestinationUrl(rw, r, requestConfig, requestLogger)
	if !ok {
		return
	}
	provider, ok := getProvider(rw, r, providers, requestConfig, requestLogger)
	if !ok {
		return
	}
	providerDeleteConfigHeader = provider.DeleteConfigHeaders
	secret, ok := getSecret(rw, r, requestConfig, provider, requestLogger)
	if !ok {
		return
	}
	headerKey, headerVal, ok = getHeader(rw, r, secret, requestConfig, requestLogger)
	if !ok {
		return
	}
	return
}

func getRequestRewriter(url *url.URL, headerKey string, headerVal string,
	providerDeleteConfigHeader func(*http.Header), requestLogger zerolog.Logger) func(req *httputil.ProxyRequest) {
	return func(req *httputil.ProxyRequest) {
		req.Out.Header.Del(forwardToHeader)
		req.Out.Header.Del(secretProviderHeader)
		req.Out.Header.Del(templateHeader)
		providerDeleteConfigHeader(&req.Out.Header)
		req.SetURL(url)
		req.Out.Header.Set(headerKey, headerVal)
		logRequest(req.Out, false, "Sending request to backend service", requestLogger)
	}
}

func getRequestConfig(
	rw http.ResponseWriter, r *http.Request, requestLogger zerolog.Logger,
) (requestConfig requestConf, ok bool) {
	ok = true
	requestConfig = requestConf{}
	missingHeaders := make([]string, 0, 0)
	forwardTo := r.Header.Get(forwardToHeader)
	if forwardTo == "" {
		missingHeaders = append(missingHeaders, forwardTo)
	}
	requestConfig.destinationUrl = forwardTo
	provider := r.Header.Get(secretProviderHeader)
	if provider == "" {
		missingHeaders = append(missingHeaders, provider)
	}
	requestConfig.secretProvider = provider
	template := r.Header.Get(templateHeader)
	if template == "" {
		missingHeaders = append(missingHeaders, template)
	}
	requestConfig.headerTemplate = template
	if len(missingHeaders) != 0 {
		missingHeadersS := strings.Join(missingHeaders, ",")
		err := fmt.Errorf("required headers not found: %s", missingHeadersS)
		ok = false
		requestLogger.Error().Err(err).Msgf(err.Error())
		http.Error(rw, makeHasuraError(err.Error()), http.StatusBadRequest)
		return
	}
	return
}

func parseDestinationUrl(
	rw http.ResponseWriter, r *http.Request,
	requestConfig requestConf, requestLogger zerolog.Logger,
) (url *url.URL, ok bool) {
	ok = true
	url, err := parseUrl(requestConfig.destinationUrl)
	if err != nil {
		ok = false
		requestLogger.Error().Msgf(err.Error())
		http.Error(rw, makeHasuraError(err.Error()), http.StatusBadRequest)
		return
	}
	url = getUrlWithSchemeAndHost(url)
	return
}

func getProvider(
	rw http.ResponseWriter, r *http.Request,
	providers map[string]provider.HttpProvider, requestConfig requestConf, requestLogger zerolog.Logger,
) (provider provider.HttpProvider, ok bool) {
	provider, ok = providers[requestConfig.secretProvider]
	if !ok {
		errMsg := fmt.Sprintf("Provider name %s sent in header %s does not exist",
			requestConfig.secretProvider, secretProviderHeader)
		requestLogger.Error().Msgf(errMsg)
		http.Error(rw, makeHasuraError(errMsg), http.StatusBadRequest)
		return
	}
	return
}

func getSecret(
	rw http.ResponseWriter, r *http.Request,
	requestConfig requestConf, provider provider.HttpProvider, requestLogger zerolog.Logger,
) (secret string, ok bool) {
	ok = true
	fetcher, err := provider.SecretFetcher(r.Header)
	if err != nil {
		ok = false
		errMsg := fmt.Sprintf("Required configurations not found in header")
		requestLogger.Error().Err(err).Msgf(errMsg)
		http.Error(rw, makeHasuraError(errMsg), http.StatusBadRequest)
		return
	}
	secret, err = fetcher.FetchSecret()
	if err != nil {
		ok = false
		errMsg := fmt.Sprintf("Unable to fetch secret")
		requestLogger.Error().Err(err).Msgf(errMsg)
		http.Error(rw, makeHasuraError(errMsg), http.StatusBadRequest)
		return
	}
	return
}

func getHeader(
	rw http.ResponseWriter, r *http.Request, secret string,
	requestConfig requestConf, requestLogger zerolog.Logger,
) (headerKey string, headerVal string, ok bool) {
	ok = true
	headerKey, headerVal, err := getHeaderFromTemplate(requestConfig.headerTemplate, secret)
	if err != nil {
		ok = false
		errMsg := fmt.Sprintf("Header template %s sent in header %s is not valid", requestConfig.headerTemplate, templateHeader)
		requestLogger.Error().Err(err).Msgf(errMsg)
		http.Error(rw, makeHasuraError(errMsg), http.StatusBadRequest)
		return
	}
	return
}
