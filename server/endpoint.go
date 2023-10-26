package server

import (
	"net/http"
	"net/http/httputil"

	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

type Config struct {
	Providers map[string]provider.HttpProvider
}

type Rewrite func(*httputil.ProxyRequest)

type Server struct {
	reverseProxy func(Rewrite) httputil.ReverseProxy
	config       Config
	logger       zerolog.Logger
}

func (s Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	requestLogger := s.logger.With().Ctx(r.Context()).Logger()
	LogRequest(r, false, "Received a request", requestLogger)

	url, headerKey, headerVal, providerHeaderDelete, ok := GetRequestRewriteDetails(
		rw, r, s.config.Providers, requestLogger,
	)
	if !ok {
		return
	}

	rewrite := GetRequestRewriter(url, headerKey, headerVal, providerHeaderDelete, requestLogger)
	reverseProxy := s.reverseProxy(rewrite)
	reverseProxy.ServeHTTP(rw, r)
}

func Create(config Config, logger zerolog.Logger) Server {
	return Server{
		reverseProxy: func(rewrite Rewrite) httputil.ReverseProxy {
			return httputil.ReverseProxy{
				Rewrite: rewrite,
			}
		},
		config: config,
		logger: logger,
	}
}
