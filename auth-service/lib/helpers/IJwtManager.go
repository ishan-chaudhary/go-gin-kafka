package jwtmanager

import (
	"github.com/golang-jwt/jwt"
)

type JWTManager struct {
	publicKey     []byte
	privateKey    []byte
}

type UserClaims struct {
	jwt.StandardClaims
	Username string `json:"username"`
	Role     string `json:"role"`
	ID       string `json:"_id"`
}
