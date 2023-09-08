package log

import (
	"net/http"

	"github.com/rs/zerolog"
)

const (
	requestLogType = "request_log"
)

/*
	Logs the request url method and headers in Debug mode.
	If form data must be shown, showForm must be set to true and
	request.ParseForm() must be called before calling this function.
*/
func LogRequest(
	request *http.Request,
	showForm bool,
	msg string,
	logger zerolog.Logger,
) {
	headerDict := zerolog.Dict()
	for k, _ := range request.Header {
		headerDict = headerDict.Str(k, request.Header.Get(k))
	}
	logger.Debug().
		Str("log_type", requestLogType).
		Str("url", request.URL.String()).
		Str("method", request.Method).
		Dict("headers", headerDict).
		Msg(msg)
}
