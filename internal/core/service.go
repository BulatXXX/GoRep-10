package core

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	jwtlib "github.com/golang-jwt/jwt/v5"

	"singularity.com/pz10-auth/internal/http/middleware"
	"singularity.com/pz10-auth/internal/repo"
)

type userRepo interface {
	CheckPassword(email, pass string) (repo.UserRecord, error)
}

type jwtSigner interface {
	SignAccess(userID int64, email, role string) (string, error)
	SignRefresh(userID int64, email, role string) (string, error)
	Parse(tokenStr string) (jwtlib.MapClaims, error) // важно: jwt.MapClaims
}

type Service struct {
	repo  userRepo
	jwt   jwtSigner
	black *RefreshBlacklist
}

func NewService(r userRepo, j jwtSigner) *Service {
	return &Service{
		repo:  r,
		jwt:   j,
		black: NewRefreshBlacklist(),
	}
}

func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email == "" || in.Password == "" {
		httpError(w, http.StatusBadRequest, "invalid_credentials")
		return
	}

	u, err := s.repo.CheckPassword(in.Email, in.Password)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	access, err := s.jwt.SignAccess(u.ID, u.Email, u.Role)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "token_error")
		return
	}

	refresh, err := s.jwt.SignRefresh(u.ID, u.Email, u.Role)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "token_error")
		return
	}

	jsonOK(w, map[string]any{
		"access":  access,
		"refresh": refresh,
	})
}

func (s *Service) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Refresh string `json:"refresh"`
	}

	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Refresh == "" {
		httpError(w, http.StatusBadRequest, "invalid_refresh")
		return
	}

	if s.black.IsRevoked(in.Refresh) {
		httpError(w, http.StatusUnauthorized, "refresh_revoked")
		return
	}

	claims, err := s.jwt.Parse(in.Refresh)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "invalid_refresh")
		return
	}

	typ, _ := claims["typ"].(string)
	if typ != "refresh" {
		httpError(w, http.StatusUnauthorized, "invalid_refresh_type")
		return
	}

	var id int64
	switch v := claims["sub"].(type) {
	case float64:
		id = int64(v)
	case int64:
		id = v
	default:
		httpError(w, http.StatusInternalServerError, "bad_claims")
		return
	}
	email, _ := claims["email"].(string)
	role, _ := claims["role"].(string)

	if expRaw, ok := claims["exp"].(float64); ok {
		exp := time.Unix(int64(expRaw), 0)
		s.black.Revoke(in.Refresh, exp)
	}

	access, err := s.jwt.SignAccess(id, email, role)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "token_error")
		return
	}
	refresh, err := s.jwt.SignRefresh(id, email, role)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "token_error")
		return
	}

	jsonOK(w, map[string]any{
		"access":  access,
		"refresh": refresh,
	})
}

func (s *Service) MeHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.CtxClaimsKey).(map[string]any)
	if !ok || claims == nil {
		httpError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	jsonOK(w, map[string]any{
		"id":    claims["sub"],
		"email": claims["email"],
		"role":  claims["role"],
	})
}

// ABAC: /api/v1/users/{id}
func (s *Service) UserHandler(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid_id")
		return
	}
	claims, ok := r.Context().Value(middleware.CtxClaimsKey).(map[string]any)
	if !ok || claims == nil {
		httpError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	role, _ := claims["role"].(string)

	var subID int64
	switch v := claims["sub"].(type) {
	case float64:
		subID = int64(v)
	case int64:
		subID = v
	default:
		httpError(w, http.StatusInternalServerError, "bad_claims")
		return
	}

	if role == "user" && subID != id {
		httpError(w, http.StatusForbidden, "forbidden")
		return
	}

	var userEmail, userRole string
	switch id {
	case 1:
		userEmail = "admin@example.com"
		userRole = "admin"
	case 2:
		userEmail = "user@example.com"
		userRole = "user"
	default:
		httpError(w, http.StatusNotFound, "not_found")
		return
	}

	jsonOK(w, map[string]any{
		"id":    id,
		"email": userEmail,
		"role":  userRole,
	})
}

func (s *Service) AdminStats(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{"users": 2, "version": "1.0"})
}

// === утилиты ===

type errorResponse struct {
	Error   string      `json:"error"`
	Details interface{} `json:"details,omitempty"`
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string, details ...interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	var det interface{}
	if len(details) > 0 {
		det = details[0]
	}

	_ = json.NewEncoder(w).Encode(errorResponse{
		Error:   msg,
		Details: det,
	})
}

// === in-memory blacklist для refresh-токенов ===

type RefreshBlacklist struct {
	mu   sync.Mutex
	data map[string]time.Time // token -> exp
}

func NewRefreshBlacklist() *RefreshBlacklist {
	return &RefreshBlacklist{
		data: make(map[string]time.Time),
	}
}

func (b *RefreshBlacklist) Revoke(token string, exp time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[token] = exp
}

func (b *RefreshBlacklist) IsRevoked(token string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	exp, ok := b.data[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(b.data, token)
		return false
	}
	return true
}
