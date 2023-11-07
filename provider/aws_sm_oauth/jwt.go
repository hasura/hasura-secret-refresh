package aws_sm_oauth

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func createJwtToken(
	rsaPrivateKeyPemRaw string, claims map[string]interface{},
	duration time.Duration, currentTime time.Time, clientId string,
	sslCert string) (
	jwtString string, err error,
) {
	rsaPrivateKeyPem, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaPrivateKeyPemRaw))
	if err != nil {
		return "", fmt.Errorf("Error parsing rsa private key: %s", err)
	}
	jwtClaims, err := makeClaims(duration, currentTime, clientId, claims)
	if err != nil {
		return "", fmt.Errorf("Failed to create claims for JWT: %s", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(jwtClaims))
	fingerprint, err := createFingerprint(sslCert)
	if err != nil {
		return "", fmt.Errorf("Failed to create fingerprint for JWT: %s", err)
	}
	token.Header["kid"] = fingerprint
	tokenString, err := token.SignedString(rsaPrivateKeyPem)
	if err != nil {
		return tokenString, err
	}
	return tokenString, nil
}

func makeClaims(
	duration time.Duration,
	currentTime time.Time,
	clientId string,
	configClaims map[string]interface{},
) (map[string]interface{}, error) {
	jwtDuration := duration
	jwtExp := currentTime.Add(jwtDuration).Unix()

	randomUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("Unable to generate random UUID for 'jti' claim: %s", err)
	}
	claimsMap := make(map[string]interface{})
	claimsMap["exp"] = jwtExp
	claimsMap["sub"] = clientId
	claimsMap["iss"] = clientId
	claimsMap["jti"] = randomUuid
	claimsMap["iat"] = currentTime.Unix()
	for k, v := range configClaims {
		claimsMap[k] = v
	}
	return claimsMap, nil
}

func createFingerprint(sslCert string) (string, error) {
	pemBlock, _ := pem.Decode([]byte(sslCert))
	if pemBlock == nil {
		return "", fmt.Errorf("unable to parse pem content for certificate")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("unable to parse x509 certificate")
	}
	fingerprintRaw := sha1.Sum(cert.Raw)
	var buf bytes.Buffer
	for _, f := range fingerprintRaw {
		fmt.Fprintf(&buf, "%02X", f)
	}
	fingerprint := strings.ToUpper(buf.String())
	return fingerprint, nil
}
