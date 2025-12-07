package config

import (
	"log"
	"os"
	"time"
)

type Config struct {
	Port       string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	ActiveKid  string
}

func Load() Config {
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	accessTTLStr := os.Getenv("JWT_ACCESS_TTL")
	if accessTTLStr == "" {
		accessTTLStr = "15m"
	}
	accessTTL, err := time.ParseDuration(accessTTLStr)
	if err != nil {
		log.Fatal("bad JWT_ACCESS_TTL")
	}

	refreshTTLStr := os.Getenv("JWT_REFRESH_TTL")
	if refreshTTLStr == "" {
		refreshTTLStr = "168h" // 7 дней
	}
	refreshTTL, err := time.ParseDuration(refreshTTLStr)
	if err != nil {
		log.Fatal("bad JWT_REFRESH_TTL")
	}

	activeKid := os.Getenv("JWT_ACTIVE_KID")
	if activeKid == "" {
		activeKid = "k1" // по умолчанию
	}

	return Config{
		Port:       ":" + port,
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
		ActiveKid:  activeKid,
	}
}
