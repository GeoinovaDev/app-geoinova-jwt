package jwt

import (
	"github.com/golang-jwt/jwt"
)

type JWTDecoder struct {
	secret []byte
}

type JWTClaimCollection struct {
	isValid bool
	claims  map[string]interface{}
}

func NewJWTDecoder(secret string) *JWTDecoder {
	return &JWTDecoder{[]byte(secret)}
}

func (decoder *JWTDecoder) Parse(token string) *JWTClaimCollection {
	_token, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return decoder.secret, nil
	})

	if _token == nil {
		return &JWTClaimCollection{
			isValid: false,
		}
	}

	return &JWTClaimCollection{
		isValid: _token.Valid,
		claims:  _token.Claims.(jwt.MapClaims),
	}
}

func (c *JWTClaimCollection) IsValid() bool {
	return c.isValid
}

func (c *JWTClaimCollection) AddClaim(name string, value interface{}) {
	c.claims[name] = value
}

func (c *JWTClaimCollection) GetClaim(name string) (interface{}, bool) {
	if _, ok := c.claims[name]; ok {
		return c.claims[name], true
	} else {
		return "", false
	}
}

func (c *JWTClaimCollection) GetClaimUInt(name string) (uint, bool) {
	value, ok := c.GetClaim(name)
	if ok {
		return value.(uint), true
	}

	return 0, false
}

func (c *JWTClaimCollection) GetClaimInt(name string) (int, bool) {
	value, ok := c.GetClaim(name)
	if ok {
		return value.(int), true
	}

	return -1, false
}

func (c *JWTClaimCollection) GetClaimInt64(name string) (int64, bool) {
	value, ok := c.GetClaim(name)
	if ok {
		return value.(int64), true
	}

	return -1, false
}

func (c *JWTClaimCollection) GetClaimFloat64(name string) (float64, bool) {
	value, ok := c.GetClaim(name)
	if ok {
		return value.(float64), true
	}

	return -1, false
}

func (c *JWTClaimCollection) GetClaimString(name string) (string, bool) {
	value, ok := c.GetClaim(name)
	if ok {
		return value.(string), true
	}

	return "", false
}

func (c *JWTClaimCollection) GetClaimBoolean(name string) (bool, bool) {
	value, ok := c.GetClaim(name)
	if ok {
		return value.(bool), true
	}

	return false, false
}
