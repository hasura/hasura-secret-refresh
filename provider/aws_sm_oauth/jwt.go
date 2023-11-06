package aws_sm_oauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func createJwtToken(
	rsaPrivateKeyPemRaw string, claims map[string]interface{},
	duration time.Duration, currentTime time.Time, clientId string) (
	jwtString string, err error,
) {
	rsaPrivateKeyPem, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaPrivateKeyPemRaw))
	if err != nil {
		return "", fmt.Errorf("Error parsing rsa private key: %s", err)
	}
	jwtClaims, err := makeClaims(duration, currentTime, clientId, claims)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(jwtClaims))
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
