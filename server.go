package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
)

const secretCacheTtl = 5 * time.Minute

type FetchSecrets func([]string) (map[string]string, error)

func ModifyHeaders(
	current map[string]string, fetch FetchSecrets) (new map[string]string, err error,
) {
	new = make(map[string]string)
	regex := regexp.MustCompile("##(.*?)##")
	secretsToFetch := make(map[string]bool)
	for _, headerVal := range current {
		matches := regex.FindAllStringSubmatch(headerVal, -1)
		for _, v := range matches {
			secretKey := v[1]
			secretsToFetch[secretKey] = true
		}
	}
	secretsToFetchList := make([]string, 0, len(secretsToFetch))
	for k, _ := range secretsToFetch {
		secretsToFetchList = append(secretsToFetchList, k)
	}
	secrets, err := fetch(secretsToFetchList)
	if err != nil {
		return
	}
	for header, headerVal := range current {
		newHeaderVal := regex.ReplaceAllStringFunc(headerVal, func(s string) string {
			matches := regex.FindStringSubmatch(s)
			secretKey := matches[1]
			secret, ok := secrets[secretKey]
			if !ok {
				//TODO: Handle error
			}
			return secret
		})
		new[header] = newHeaderVal
	}
	return
}

// Fetch secrets from aws secrets manager
func fetchSecretsAws(
	secretIds []string, cache *secretcache.Cache) (secrets map[string]string, err error,
) {
	secrets = make(map[string]string)
	for _, secretId := range secretIds {
		var secret string
		secret, err = cache.GetSecretString(secretId)
		if err != nil {
			//TODO: handle error
		}
		secrets[secretId] = secret
	}
	return
}

func main() {
	secretsCache, err := secretcache.New(
		func(c *secretcache.Cache) { c.CacheConfig.CacheItemTTL = secretCacheTtl.Nanoseconds() },
	)
	if err != nil {
		// TODO: handle error
	}
	fetchSecrets := func(s []string) (map[string]string, error) {
		return fetchSecretsAws(s, secretsCache)
	}

	rewrite := func(req *httputil.ProxyRequest) {
		headers := make(map[string]string)
		for k, _ := range req.In.Header {
			headers[k] = req.In.Header.Get(k)
		}
		newHeaders, err := ModifyHeaders(headers, fetchSecrets)
		forwardToHeader := "X-Proxy-Forward-To"
		forwardTo := req.In.Header.Get(forwardToHeader)
		url, err := url.Parse(forwardTo)
		if err != nil {
			// TODO: handle error
		}
		for k, v := range newHeaders {
			req.Out.Header.Set(k, v)
		}
		req.Out.Header.Del(forwardToHeader)
		req.SetURL(url)
	}

	// https://pkg.go.dev/net/http/httputil#ReverseProxy
	http.Handle("/", &httputil.ReverseProxy{
		Rewrite: rewrite,
	})
	http.ListenAndServe(":5353", nil)
}
