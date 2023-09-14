package server

import (
	"net/http"
	"net/http/httputil"

	"github.com/rs/zerolog"
)

func Serve(config Config, logger zerolog.Logger) {
	http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		requestLogger := logger.With().Ctx(r.Context()).Logger()
		LogRequest(r, false, "Received a request", requestLogger)

		url, headerKey, headerVal, providerHeaderDelete, ok := GetRequestRewriteDetails(rw, r, config.Providers, requestLogger)
		if !ok {
			return
		}

		reverseProxy := httputil.ReverseProxy{
			Rewrite: GetRequestRewriter(url, headerKey, headerVal, providerHeaderDelete, requestLogger),
		}
		reverseProxy.ServeHTTP(rw, r)
	})
	http.ListenAndServe(":5353", nil)
}
