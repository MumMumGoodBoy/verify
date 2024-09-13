package verify

import (
	"crypto"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid token")

type Claims struct {
	jwt.RegisteredClaims
	UserId  uint `json:"userId"`
	IsAdmin bool `json:"isAdmin"`
}

type JWTVerifier struct {
	publicKey crypto.PublicKey
	parser    *jwt.Parser
}

func NewJWTVerifier(key string) (*JWTVerifier, error) {
	public, err := jwt.ParseEdPublicKeyFromPEM([]byte(key))
	if err != nil {
		return nil, err
	}

	return &JWTVerifier{
		publicKey: public,
		parser: jwt.NewParser(
			jwt.WithExpirationRequired(),
			jwt.WithIssuer("user-management-service"),
			jwt.WithIssuedAt(),
		),
	}, nil
}

func (j *JWTVerifier) Verify(token string) (Claims, error) {
	claims := Claims{}
	res, err := j.parser.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return j.publicKey, nil
	})
	if err != nil {
		return Claims{}, err
	}

	if !res.Valid {
		return Claims{}, ErrInvalidToken
	}

	return claims, nil
}
