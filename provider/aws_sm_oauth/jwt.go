package aws_sm_oauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func CreateJwtToken(
	rsaPrivateKeyPemRaw string, claims map[string]interface{},
	duration time.Duration, currentTime time.Time) (
	jwtString string, err error,
) {
	rsaPrivateKeyPem, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaPrivateKeyPemRaw))
	if err != nil {
		return "", fmt.Errorf("Error parsing rsa private key: %s", err)
	}
	jwtDuration := duration
	currentJwtClaim := make(map[string]interface{})
	jwtExp := currentTime.Add(jwtDuration).Unix()
	for k, v := range claims {
		currentJwtClaim[k] = v
	}
	currentJwtClaim["exp"] = jwtExp
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(currentJwtClaim))
	tokenString, err := token.SignedString(rsaPrivateKeyPem)
	if err != nil {
		return tokenString, err
	}
	return tokenString, nil
}
