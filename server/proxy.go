package server

import (
	"net/http"
	"net/http/httputil"

	"github.com/hasura/hasura-secret-refresh/provider"
	"github.com/rs/zerolog"
)

type DeploymentType string

const (
	InitContainer DeploymentType = "initcontainer"
	Sidecar       DeploymentType = "sidecar"
)

type Config struct {
	Providers      map[string]provider.HttpProvider
	DeploymentType DeploymentType
}

type rewriteRequest func(*httputil.ProxyRequest)

type Server struct {
	reverseProxy func(rewriteRequest) httputil.ReverseProxy
	config       Config
	logger       zerolog.Logger
}

func (s Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	requestLogger := s.logger.With().Ctx(r.Context()).Logger()
	logRequest(r, false, "Received a request", requestLogger)

	url, headerKey, headerVal, providerHeaderDelete, ok := getRequestRewriteDetails(
		rw, r, s.config.Providers, requestLogger,
	)
	if !ok {
		return
	}

	rewrite := getRequestRewriter(url, headerKey, headerVal, providerHeaderDelete, requestLogger)
	reverseProxy := s.reverseProxy(rewrite)
	reverseProxy.ServeHTTP(rw, r)
}

func Create(config Config, logger zerolog.Logger) Server {
	return Server{
		reverseProxy: func(rewrite rewriteRequest) httputil.ReverseProxy {
			return httputil.ReverseProxy{
				Rewrite: rewrite,
			}
		},
		config: config,
		logger: logger,
	}
}
