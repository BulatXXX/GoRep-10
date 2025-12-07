package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

type Validator interface {
	Parse(tokenStr string) (jwtlib.MapClaims, error)
}

type Signer interface {
	SignAccess(userID int64, email, role string) (string, error)
	SignRefresh(userID int64, email, role string) (string, error)
	Parse(tokenStr string) (jwtlib.MapClaims, error)
}

// RS256 с двумя ключами и активным kid
type RS256 struct {
	privateKeys map[string]*rsa.PrivateKey
	publicKeys  map[string]*rsa.PublicKey
	activeKid   string

	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewRS256(accessTTL, refreshTTL time.Duration, activeKid string) *RS256 {
	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)

	privs := map[string]*rsa.PrivateKey{
		"k1": k1,
		"k2": k2,
	}

	pubs := map[string]*rsa.PublicKey{
		"k1": &k1.PublicKey,
		"k2": &k2.PublicKey,
	}

	if activeKid != "k1" && activeKid != "k2" {
		activeKid = "k1"
	}

	return &RS256{
		privateKeys: privs,
		publicKeys:  pubs,
		activeKid:   activeKid,
		accessTTL:   accessTTL,
		refreshTTL:  refreshTTL,
	}
}

func (r *RS256) SignAccess(userID int64, email, role string) (string, error) {
	return r.signWithTTL(userID, email, role, tokenTypeAccess, r.accessTTL)
}

func (r *RS256) SignRefresh(userID int64, email, role string) (string, error) {
	return r.signWithTTL(userID, email, role, tokenTypeRefresh, r.refreshTTL)
}

func (r *RS256) signWithTTL(userID int64, email, role, typ string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwtlib.MapClaims{
		"sub":   userID,
		"email": email,
		"role":  role,
		"typ":   typ,
		"iss":   "pz10-auth",
		"aud":   "pz10-clients",
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = r.activeKid

	priv, ok := r.privateKeys[r.activeKid]
	if !ok {
		return "", errors.New("unknown active kid")
	}
	return token.SignedString(priv)
}

func (r *RS256) Parse(tokenStr string) (jwtlib.MapClaims, error) {
	token, err := jwtlib.Parse(tokenStr, func(t *jwtlib.Token) (any, error) {
		if _, ok := t.Method.(*jwtlib.SigningMethodRSA); !ok {
			return nil, errors.New("invalid signing method")
		}

		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		pub, ok := r.publicKeys[kid]
		if !ok {
			return nil, errors.New("unknown kid")
		}
		return pub, nil
	},
		jwtlib.WithIssuer("pz10-auth"),
		jwtlib.WithAudience("pz10-clients"),
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}
	return claims, nil
}
