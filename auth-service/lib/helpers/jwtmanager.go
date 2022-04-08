package jwtmanager

import (
	"fmt"
	"io/ioutil"
	"log"

	"swiggy/gin/services/user"

	"github.com/golang-jwt/jwt"
)

var Manager *JWTManager

func init() {
	prvKey, err := ioutil.ReadFile("keys/private-key")
	if err != nil {
		log.Fatalln(err)
	}
	pubKey, err := ioutil.ReadFile("keys/public-key")
	if err != nil {
		log.Fatalln(err)
	}
	Manager = &JWTManager{
		privateKey: prvKey,
		publicKey:  pubKey,
	}
}

func (manager *JWTManager) Generate(user *user.User) (string, error) {
	claims := UserClaims{
		Username: user.Username,
		Role:     user.Role,
		ID:       user.ID.Hex(),
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(manager.privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil

}

func (manager *JWTManager) Verify(accessToken string) (*UserClaims, error) {

	key, err := jwt.ParseRSAPublicKeyFromPEM(manager.publicKey)
	if err != nil {
		return nil, fmt.Errorf("validate: parse key: %w", err)
	}

	token, err := jwt.ParseWithClaims(
		accessToken,
		&UserClaims{},
		func(jwtToken *jwt.Token) (interface{}, error) {
			if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
			}

			return key, nil
		},
	)

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
