package requestconfig

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type ParseRequestConfigInput struct {
	HeaderName   string
	UpdateConfig func(headerVal string)
}

func ParseRequestConfig(headers http.Header, requestConfigs []ParseRequestConfigInput) error {
	notFoundHeaders := make([]string, 0, 0)
	for _, v := range requestConfigs {
		val := headers.Get(v.HeaderName)
		if val == "" {
			notFoundHeaders = append(notFoundHeaders, v.HeaderName)
		}
		v.UpdateConfig(val)
	}
	if len(notFoundHeaders) != 0 {
		notFoundHeadersString := strings.Join(notFoundHeaders, ", ")
		return errors.New(fmt.Sprintf("Header(s) %s not found in request", notFoundHeadersString))
	}
	return nil
}
