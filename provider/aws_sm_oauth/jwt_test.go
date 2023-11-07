package aws_sm_oauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	// openssl genrsa -out example.key 2048
	testRsaPrivateKeyPem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAy1D4HMcb/9jZCdjXLcBZn7Nf6WeA+t0azisu/eobV7Bk8/VA\nnA4Pe9IygH+c9JtzTbECKkHHRT/H9M6FHqUF6AxeYRDFj3uNXBAQSlyNEhu1VDL8\nOpvr0EGMS1YW4Rc36Ul7C9DC55OoYHfMio+BymG/wzvwhuNVeEq5BsnO3AKkWQNJ\nieA7cOTgg/0dBCKU3OASG0+ZTtYSswTVjUr9+U2HsNB4VeBp/IRiy9rVk9WYpvgy\nEqX4SISXOd7lWoAl7rv6x2YvOI9fgYrbASZt5eILUw3tePxfHjMtVSIj4+5HWHei\nfMlO6I/iT/xRYbS4SBnWweYqRHGBwKv+RyzGTwIDAQABAoIBACCwZwPxe236RoMP\nyyD/ASntJCmZy6IJ9KpbRRXsEvNZWBHlR7sPg6vL0vTYD7tAVxyRriBvLQPUSmjw\n33Ra4gU6H96JXMpB+itoJcZe9QuJSvE7tVQTB6oXL+BY+hq8qe+nMdJngT7MfdDs\n0gUhJ6QLbVKNi5GUcYSCtxcBUXIL7Q62HYUj/PU/prNIEn1IAgE/MOEy6uAAf826\nlRuvNBBasEHzLbuFMIqtB7M97F959XORJ3bmbZrxsxS3mtl62RsPKQCNgesP7Fy8\nfmHaon+R2seNC+SbvWU5DeS6Om2bdzhPH+eVR9GQz0mWipMQb5eWwJjIm8Mk4Ji8\nJfX2dikCgYEA+OOvz9ZeHUapy8eZUrDv8muGDGuA+Y1A7FtnRQWXhmDnoMHSwjgW\nuKsp4QSejbOj75EGIsmhX+3EWj5SOxumz7iDl34JTkSP60OXwy/+uZ1zV+cEZQbX\nxyUPz78pPOb/4l7R1a0KBDQOezitoBgpttBBDMsKmlWf47XRCUS+alUCgYEA0R/4\n68kxEPFKwLMv+VPwWZMqf1ksxEYnN9RQaBJlRD7maNl6pU+xQAHxRlIqVftMrbzW\n/nJ+IefZ0hKvr2Tg5xZQY+BrOc/HAXRsWSOEEQme0kqip9496MfIi/iPT5uVFsYi\nFv4Gfd/0Xy92DAo6pSUviwa96J3skTMYNogFWhMCgYAGWI/YBcg6iN21c25mXFqR\n3Mn7MRaFxmM8Y4w7h0v4winFwItmJlX1+W9E7IA6brUkW5dDdc6mioJyJpqkJS1Y\nqIS6bR1BoJ/myL9q26NsCiaxvBMxnD4ONtSzYFVl1yH5HJ/PCe1yc/1WiPhsV5Fg\ntuihsd+gVcSQ4sbkrJsKTQKBgHE9fu0u5QLnpjLy1OeOLHhU2I5dG4Cs/E+fCGtS\nisOJy/q6yU76+GBQrPYHSCWHDt6Fg2YFWYfCpJC8zaWMWrzHuIBc5bNIb9q50HH0\naW9QZlA5WhrMnXmPtWkWD4RsGy9Z2tvYcmt2+j0Q1jtuzpLer//4hp2P5qo5oMLm\npP9BAoGAX72GGWjRQpLznAO8m3EIDe5aAPttCwS3azXH5ZW9EZkYVa1lhsZeTTUV\nnrc54RJm7CRz4oQPrLZZIhUeh+5myv7GkpWj4aQ0gEFvoDtnsYr5F6DZPYIbOe19\n3raz7Yu4waa1Yu3egq16lyRGuyBedAnnGU0PsgVhDwdBBbCDmFY=\n-----END RSA PRIVATE KEY-----\n"

	// openssl req -new -key example.key -out example.csr
	// openssl x509 -req -days 365 -in example.csr -signkey example.key -out example.crt
	testSslCert = "-----BEGIN CERTIFICATE-----\nMIIDFTCCAf0CFHCwiVmMlx4SFn2hWxEJCqE5mfNpMA0GCSqGSIb3DQEBCwUAMEcx\nCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTENMAsGA1UECgwEVGVzdDEcMBoGCSqG\nSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTAeFw0yMzExMDYwNDMyMjNaFw0yNDExMDUw\nNDMyMjNaMEcxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTENMAsGA1UECgwEVGVz\ndDEcMBoGCSqGSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEB\nBQADggEPADCCAQoCggEBAMtQ+BzHG//Y2QnY1y3AWZ+zX+lngPrdGs4rLv3qG1ew\nZPP1QJwOD3vSMoB/nPSbc02xAipBx0U/x/TOhR6lBegMXmEQxY97jVwQEEpcjRIb\ntVQy/Dqb69BBjEtWFuEXN+lJewvQwueTqGB3zIqPgcphv8M78IbjVXhKuQbJztwC\npFkDSYngO3Dk4IP9HQQilNzgEhtPmU7WErME1Y1K/flNh7DQeFXgafyEYsva1ZPV\nmKb4MhKl+EiElzne5VqAJe67+sdmLziPX4GK2wEmbeXiC1MN7Xj8Xx4zLVUiI+Pu\nR1h3onzJTuiP4k/8UWG0uEgZ1sHmKkRxgcCr/kcsxk8CAwEAATANBgkqhkiG9w0B\nAQsFAAOCAQEAHwIDyWERgqINnDnry7SOe5+239xbSLPlEiLKb/qTgDJ8U+TBvAth\nMXLgvnuiWb0FXYGkaNcTLJcwDCn9OnyXp95xwg56Ip/FbAVolaGgrHStOJeRKyAn\n/RfiDEG1mBMZdJiKk4v9uGyfsEh2ZrYZOWSFUcKxpAmPrTBXSUapO8vgKdJ2+MHb\nDO9F23P3p3EwimPjw+fJpBiwGGyVG99f0fAs2cw3JEiwrJmTd/Oo6sUkX7wKNtZw\nCiPAFrrF1O/C+xF8P4LREodrfPZ9egpECenFNWUrcYyqLzthL7BW2zeI52tCOVaT\nw/wyQ3Hu+2oN2JegWr40bBTE2Sx5X+F4UQ==\n-----END CERTIFICATE-----\n"

	// openssl x509 -noout -fingerprint -sha1 -inform pem -in example.crt
	testSslFingerprint = "E013561F31BD801DD734082A286BA6E3840CE827"
)

func TestJwt_TestJwtCreation(t *testing.T) {
	mockClaims := map[string]interface{}{
		"aud": "audience_claim",
	}
	fiveMins := time.Minute * 5
	currentTime := time.Date(2023, time.January, int(time.Saturday), 0, 0, 0, 0, time.UTC)
	fiveMinsLater := currentTime.Add(fiveMins)
	token, err := createJwtToken(testRsaPrivateKeyPem, mockClaims, fiveMins, currentTime, "mock_client_id", testSslCert)
	if err != nil {
		t.Fatalf("Jwt creation failed")
	}
	block, _ := pem.Decode([]byte(testSslCert))
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	keyfunc := func(_ *jwt.Token) (interface{}, error) {
		return rsaPublicKey, nil
	}
	decodedToken, _ := jwt.Parse(token, keyfunc)
	alg, ok := decodedToken.Header["alg"]
	if !ok {
		t.Fatalf("'alg' not found in JWT header")
	}
	if alg != "RS256" {
		t.Fatalf("'alg' must be 'RS256'")
	}
	kid, ok := decodedToken.Header["kid"]
	if !ok {
		t.Fatalf("'kid' not found in JWT header")
	}
	if kid != testSslFingerprint {
		t.Fatalf("'kid' must be %s but received %s", testSslFingerprint, kid)
	}
	claimsMap, ok := decodedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("Claims is not of the expected type")
	}
	val, found := claimsMap["exp"]
	if !found {
		t.Fatalf("Claims 'exp' not found in token")
	}
	valFloat := val.(float64)
	if int64(valFloat) != fiveMinsLater.Unix() {
		t.Fatalf("Expected to have value %d in claim 'exp' but received %d",
			fiveMinsLater.Unix(), int64(valFloat),
		)
	}
	val, found = claimsMap["aud"]
	if !found {
		t.Fatalf("Claims 'aud' not found in token")
	}
	valStr := val.(string)
	if valStr != "audience_claim" {
		t.Fatalf("Expected to have value %s in claim 'aud' but received %s",
			"sub_claim", valStr,
		)
	}
	val, found = claimsMap["iss"]
	if !found {
		t.Fatalf("Claims 'iss' not found in token")
	}
	valStr = val.(string)
	if valStr != "mock_client_id" {
		t.Fatalf("Expected to have value %s in claim 'iss' but received %s",
			"mock_client_id", valStr,
		)
	}
	val, found = claimsMap["jti"]
	if !found {
		t.Fatalf("Claims 'jti' not found in token")
	}
	valStr = val.(string)
	_, err = uuid.Parse(valStr)
	if err != nil {
		t.Fatalf("Expected to have valid UUID in claim 'jti'. Parsing uuid resulted in error: %s",
			err,
		)
	}
	val, found = claimsMap["iat"]
	if !found {
		t.Fatalf("Claims 'iat' not found in token")
	}
	valFloat = val.(float64)
	if int64(valFloat) != currentTime.Unix() {
		t.Fatalf("Expected to have value %d in claim 'iat' but received %d",
			currentTime.Unix(), int64(valFloat),
		)
	}
	val, found = claimsMap["sub"]
	if !found {
		t.Fatalf("Claims 'sub' not found in token")
	}
	valStr = val.(string)
	if valStr != "mock_client_id" {
		t.Fatalf("Expected to have value %s in claim 'sub' but received %s",
			"mock_client_id", valStr,
		)
	}
	if len(claimsMap) != 6 {
		t.Errorf("Unknown claims are present in the token")
	}
}

func TestJwt_TestJwtCreationFailure(t *testing.T) {
	mockClaims := map[string]interface{}{
		"sub": "sub_claim",
		"aud": "audience_claim",
	}
	fiveMins := time.Minute * 5
	currentTime := time.Date(2023, time.January, int(time.Saturday), 0, 0, 0, 0, time.UTC)
	_, err := createJwtToken("invalid_rsa_key", mockClaims, fiveMins, currentTime, "mock_client_id", testSslCert)
	if err == nil {
		t.Fatalf("Expected error because rsa key was invalid")
	}
}
