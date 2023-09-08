package server

import (
	"net/http"
	"net/http/httputil"

	"github.com/hasura/hasura-secret-refresh/log"
	"github.com/rs/zerolog"
)

func Serve(config Config, logger zerolog.Logger) {
	http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		requestLogger := logger.With().Ctx(r.Context()).Logger()
		log.LogRequest(r, false, "Received a request", requestLogger)

		url, headerKey, headerVal := GetRequestRewriteDetails(rw, r, config.Providers, requestLogger)

		reverseProxy := httputil.ReverseProxy{
			Rewrite: GetRequestRewriter(url, headerKey, headerVal),
		}
		reverseProxy.ServeHTTP(rw, r)
	})
	http.ListenAndServe(":5353", nil)
}
