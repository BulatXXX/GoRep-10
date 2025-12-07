package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"singularity.com/pz10-auth/internal/core"
	"singularity.com/pz10-auth/internal/http/middleware"
	"singularity.com/pz10-auth/internal/platform/config"
	"singularity.com/pz10-auth/internal/platform/jwt"
	"singularity.com/pz10-auth/internal/repo"
)

func Build(cfg config.Config) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logging())

	// DI
	userRepo := repo.NewUserMem() // храним заранее захэшированных юзеров (email, bcrypt)
	jwtv := jwt.NewRS256(cfg.AccessTTL, cfg.RefreshTTL, cfg.ActiveKid)
	svc := core.NewService(userRepo, jwtv)

	// Публичные маршруты
	r.With(middleware.RateLimitLogin()).
		Post("/api/v1/login", svc.LoginHandler)

	r.Post("/api/v1/refresh", svc.RefreshHandler)

	// Защищённые маршруты
	r.Group(func(priv chi.Router) {
		priv.Use(middleware.AuthN(jwtv))                 // аутентификация JWT
		priv.Use(middleware.AuthZRoles("admin", "user")) // базовая RBAC
		priv.Get("/api/v1/me", svc.MeHandler)            // вернёт профиль из токена
		priv.Get("/api/v1/users/{id}", svc.UserHandler)
	})

	// Пример только для админов
	r.Group(func(admin chi.Router) {
		admin.Use(middleware.AuthN(jwtv))
		admin.Use(middleware.AuthZRoles("admin"))
		admin.Get("/api/v1/admin/stats", svc.AdminStats)
	})

	return r
}
