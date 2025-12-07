package jwt

import (
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

type Validator interface {
	Parse(tokenStr string) (jwtv5.MapClaims, error)
}

// для сервиса авторизации
type Signer interface {
	SignAccess(userID int64, email, role string) (string, error)
	SignRefresh(userID int64, email, role string) (string, error)
}

type HS256 struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewHS256(secret []byte, accessTTL, refreshTTL time.Duration) *HS256 {
	return &HS256{
		secret:     secret,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// старый метод, если где-то используется — пусть даёт access
func (h *HS256) Sign(userID int64, email, role string) (string, error) {
	return h.SignAccess(userID, email, role)
}

func (h *HS256) SignAccess(userID int64, email, role string) (string, error) {
	return h.signWithTTL(userID, email, role, tokenTypeAccess, h.accessTTL)
}

func (h *HS256) SignRefresh(userID int64, email, role string) (string, error) {
	return h.signWithTTL(userID, email, role, tokenTypeRefresh, h.refreshTTL)
}

func (h *HS256) signWithTTL(userID int64, email, role, typ string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwtv5.MapClaims{
		"sub":   userID,
		"email": email,
		"role":  role,
		"typ":   typ, // ВАЖНО: тип токена
		"iss":   "pz10-auth",
		"aud":   "pz10-clients",
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
	}
	t := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	return t.SignedString(h.secret)
}

func (h *HS256) Parse(tokenStr string) (jwtv5.MapClaims, error) {
	t, err := jwtv5.Parse(tokenStr, func(t *jwtv5.Token) (any, error) {
		return h.secret, nil
	},
		jwtv5.WithValidMethods([]string{"HS256"}),
		jwtv5.WithAudience("pz10-clients"),
		jwtv5.WithIssuer("pz10-auth"),
	)
	if err != nil || !t.Valid {
		return nil, err
	}
	return t.Claims.(jwtv5.MapClaims), nil
}
