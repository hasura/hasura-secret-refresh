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
	ForwardToHeader      = "X-Hasura-Forward-To"
	SecretProviderHeader = "X-Hasura-Secret-Provider"
	TemplateHeader       = "X-Hasura-Secret-Header"
)

type RequestConfig struct {
	DestinationUrl string
	SecretProvider string
	HeaderTemplate string
}

func GetRequestRewriteDetails(
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

func GetRequestRewriter(url *url.URL, headerKey string, headerVal string,
	providerDeleteConfigHeader func(*http.Header), requestLogger zerolog.Logger) func(req *httputil.ProxyRequest) {
	return func(req *httputil.ProxyRequest) {
		req.Out.Header.Del(ForwardToHeader)
		req.Out.Header.Del(SecretProviderHeader)
		req.Out.Header.Del(TemplateHeader)
		providerDeleteConfigHeader(&req.Out.Header)
		req.SetURL(url)
		req.Out.Header.Set(headerKey, headerVal)
		LogRequest(req.Out, false, "Sending request to backend service", requestLogger)
	}
}

func getRequestConfig(
	rw http.ResponseWriter, r *http.Request, requestLogger zerolog.Logger,
) (requestConfig RequestConfig, ok bool) {
	ok = true
	requestConfig = RequestConfig{}
	missingHeaders := make([]string, 0, 0)
	forwardTo := r.Header.Get(ForwardToHeader)
	if forwardTo == "" {
		missingHeaders = append(missingHeaders, forwardTo)
	}
	provider := r.Header.Get(SecretProviderHeader)
	if provider == "" {
		missingHeaders = append(missingHeaders, provider)
	}
	template := r.Header.Get(TemplateHeader)
	if template == "" {
		missingHeaders = append(missingHeaders, template)
	}
	if len(missingHeaders) != 0 {
		missingHeadersS := strings.Join(missingHeaders, ",")
		err := fmt.Errorf("required headers not found: %s", missingHeadersS)
		ok = false
		requestLogger.Error().Err(err).Msgf(err.Error())
		http.Error(rw, MakeHasuraError(err.Error()), http.StatusBadRequest)
		return
	}
	return
}

func parseDestinationUrl(
	rw http.ResponseWriter, r *http.Request,
	requestConfig RequestConfig, requestLogger zerolog.Logger,
) (url *url.URL, ok bool) {
	ok = true
	url, err := ParseUrl(requestConfig.DestinationUrl)
	if err != nil {
		ok = false
		requestLogger.Error().Msgf(err.Error())
		http.Error(rw, MakeHasuraError(err.Error()), http.StatusBadRequest)
		return
	}
	url = GetUrlWithSchemeAndHost(url)
	return
}

func getProvider(
	rw http.ResponseWriter, r *http.Request,
	providers map[string]provider.HttpProvider, requestConfig RequestConfig, requestLogger zerolog.Logger,
) (provider provider.HttpProvider, ok bool) {
	provider, ok = providers[requestConfig.SecretProvider]
	if !ok {
		errMsg := fmt.Sprintf("Provider name %s sent in header %s does not exist",
			requestConfig.SecretProvider, SecretProviderHeader)
		requestLogger.Error().Msgf(errMsg)
		http.Error(rw, MakeHasuraError(errMsg), http.StatusBadRequest)
		return
	}
	return
}

func getSecret(
	rw http.ResponseWriter, r *http.Request,
	requestConfig RequestConfig, provider provider.HttpProvider, requestLogger zerolog.Logger,
) (secret string, ok bool) {
	ok = true
	fetcher, err := provider.SecretFetcher(r.Header)
	if err != nil {
		ok = false
		errMsg := fmt.Sprintf("Required configurations not found in header")
		requestLogger.Error().Err(err).Msgf(errMsg)
		http.Error(rw, MakeHasuraError(errMsg), http.StatusBadRequest)
		return
	}
	secret, err = fetcher.FetchSecret()
	if err != nil {
		ok = false
		errMsg := fmt.Sprintf("Unable to fetch secret")
		requestLogger.Error().Err(err).Msgf(errMsg)
		http.Error(rw, MakeHasuraError(errMsg), http.StatusBadRequest)
		return
	}
	return
}

func getHeader(
	rw http.ResponseWriter, r *http.Request, secret string,
	requestConfig RequestConfig, requestLogger zerolog.Logger,
) (headerKey string, headerVal string, ok bool) {
	ok = true
	headerKey, headerVal, err := GetHeaderFromTemplate(requestConfig.HeaderTemplate, secret)
	if err != nil {
		ok = false
		errMsg := fmt.Sprintf("Header template %s sent in header %s is not valid", requestConfig.HeaderTemplate, TemplateHeader)
		requestLogger.Error().Err(err).Msgf(errMsg)
		http.Error(rw, MakeHasuraError(errMsg), http.StatusBadRequest)
		return
	}
	return
}
