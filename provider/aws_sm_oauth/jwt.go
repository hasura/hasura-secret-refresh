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
	jwtDuration := duration
	currentJwtClaim := make(map[string]interface{})
	jwtExp := currentTime.Add(jwtDuration).Unix()
	currentJwtClaim["exp"] = jwtExp
	currentJwtClaim["sub"] = clientId
	currentJwtClaim["iss"] = clientId
	randomUuid, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("Unable to generate random UUID for 'jti' claim: %s", err)
	}
	currentJwtClaim["jti"] = randomUuid
	currentJwtClaim["iat"] = currentTime.Unix()
	for k, v := range claims {
		currentJwtClaim[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(currentJwtClaim))
	tokenString, err := token.SignedString(rsaPrivateKeyPem)
	if err != nil {
		return tokenString, err
	}
	return tokenString, nil
}
