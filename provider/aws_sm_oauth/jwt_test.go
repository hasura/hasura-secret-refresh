package aws_sm_oauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	testRsaPrivateKeyPem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAspCV0LNP43/U+qCVl+uhI40LYQTBxl1LCH+bABJrjSYhB0hs\n/ANAmkklggxFSqhwu2C3CzVZ6bGBl0wvNQi/uk9uEOyoWtocecMfDHu3sWdmy0+c\nBbvknImW4HqEkL7XJ+j/JKVhQ8g58d01exbCucyabtNds0czAvHOaqhB/mHyDNJG\njgwHzdwBjHFm4iZqQSyUEeIwNKZuVADcgdmZ9HyoP31z/wP9pXRKIf/n/JqClGvD\n1fDCfxUd9eVfIy6dPwtGpagX2YY4TQ0XvxSgTyhZo8Iae0vzHzhFI2c0J4hgIj/N\nvbBOGDuO/bzQRHp9dJrE0oYjB49BH0tFxFLxjwIDAQABAoIBAAhsseTK0PYWzeGV\nOfmU8GFRAjxtkQbe1+9qtdFnDRP3vI8vZ5TsQlwFH3PnSE2hbNAqW/h3Z+qSqV6O\nBZwm8YTEwpih0b+Xkshb4FcibyQ7kKn+84mBt+N6yleE8EQz/MqxP3hnJROhmrpC\niYdpJ37EnHSmHEGdFlcJOYfmsFZkDG6gqZks/GAYE/QubFXTAyxs5Flaq/GX3SYi\n181gfoNojiGogETA88A7oMmM1an3huR/qKEk8A/VYaM/llrYpWlXHF4zZR+cA1yL\nQgh/ogsD5H2ztUEh1CxvD2mUmJzxca7LDNdO0BRoP7JEmRJPCU6uX8/0d6GeYvgl\n7XxyxYECgYEA1zB/ecD98iAxazp6HXsGYHEBlVqo4C/1r/XF7+4P+1zQMYinsocy\nKxgn8HfHLeSQ+2KKXmrBjto/fx+5LkvtXNK90Yxi3KlJw/pc152rn4Ghmalpwmi5\niius+AtdvEHfbzdQmMD/Q93tUJNSqFbV7CVojtMx6mBTS+NHXkYbKBECgYEA1G3z\nZvo2XCE1rXsqk5DoUWTccR34S1wjGpnXvdz0BO8ufSeMZ/JBDmWbv5HpTzkObLLU\nDkCp9/fXJ4+Hy0yTB/Vd3/XapejwXmtPVViULUrh3VIXMEL/6+kCiaVy7qmL6Ufv\nPL13InfgnZYbDy42pggE9uF/+JA3RdTx4qjrH58CgYEAyO+UWRCJEGpXOxVjqduS\n3MMpA1mgj5a5CBGrPptBeSn1jgtY7C+p/OuVf8mYx5XCe7pMElYFX2sUF5R7ymtD\nvYVbkixQtFOvebxyrTOhalQVnfK/urUna4nU/dk/MecgyC0SqVCuC6VTUAYBDQfo\nwZU8yQEUfxJrNVWI8tLr0MECgYEAobwIyomMY76hKLESrIFyb64ULEd+KJpA29rv\nqE2WuD8GrSE0RFvsbjKsT0GfWcL+GYJZ83QGNJZNCIC+CeoGM9P7oi2ESDc+8xRO\ntZMYVheiOahroUIRqaKhXP1LsSwDKxyqqBs0nliY+kIz3e34i5alePYdQblDa/aC\nJ2kmgs8CgYBYbgGksrsZucOnKK2hE1JT5K2JxP6MYnn7wHm4D/IFmiuSBp9jixxq\nIMKIkdRqJCbtMLVriPpbrwF2pa7c+Lx/SYjbfMdnAC5gKShXki1WvwgdkdbY/ab8\nvwQ7aIlFBMhTWZqxRtN5J4K/Znv9xNcegN7+QBdj84BzZMkqb507iw==\n-----END RSA PRIVATE KEY-----\n"
	testRsaPublicKeyPem  = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAspCV0LNP43/U+qCVl+uh\nI40LYQTBxl1LCH+bABJrjSYhB0hs/ANAmkklggxFSqhwu2C3CzVZ6bGBl0wvNQi/\nuk9uEOyoWtocecMfDHu3sWdmy0+cBbvknImW4HqEkL7XJ+j/JKVhQ8g58d01exbC\nucyabtNds0czAvHOaqhB/mHyDNJGjgwHzdwBjHFm4iZqQSyUEeIwNKZuVADcgdmZ\n9HyoP31z/wP9pXRKIf/n/JqClGvD1fDCfxUd9eVfIy6dPwtGpagX2YY4TQ0XvxSg\nTyhZo8Iae0vzHzhFI2c0J4hgIj/NvbBOGDuO/bzQRHp9dJrE0oYjB49BH0tFxFLx\njwIDAQAB\n-----END PUBLIC KEY-----\n"
)

func TestJwt_TestJwtCreation(t *testing.T) {
	mockClaims := map[string]interface{}{
		"aud": "audience_claim",
	}
	fiveMins := time.Minute * 5
	currentTime := time.Date(2023, time.January, int(time.Saturday), 0, 0, 0, 0, time.UTC)
	fiveMinsLater := currentTime.Add(fiveMins)
	token, err := createJwtToken(testRsaPrivateKeyPem, mockClaims, fiveMins, currentTime, "mock_client_id")
	if err != nil {
		t.Fatalf("Jwt creation failed")
	}
	keyfunc := func(_ *jwt.Token) (interface{}, error) {
		return testRsaPublicKeyPem, nil
	}
	decodedToken, _ := jwt.Parse(token, keyfunc)
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
	_, err := createJwtToken("invalid_rsa_key", mockClaims, fiveMins, currentTime, "mock_client_id")
	if err == nil {
		t.Fatalf("Expected error because rsa key was invalid")
	}
}
