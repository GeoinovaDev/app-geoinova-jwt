package jwt

import (
	"github.com/golang-jwt/jwt"
)

type JWTEncoder struct {
	secret string
	claims jwt.MapClaims
}

func NewJWTEncoder(secret string) *JWTEncoder {
	return &JWTEncoder{
		secret: secret,
		claims: jwt.MapClaims{},
	}
}

func (e *JWTEncoder) AddClaim(name string, value interface{}) *JWTEncoder {
	e.claims[name] = value
	return e
}

func (e *JWTEncoder) String() string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, e.claims)

	tokenString, err := token.SignedString([]byte(e.secret))
	if err != nil {
		return ""
	}

	return tokenString
}
