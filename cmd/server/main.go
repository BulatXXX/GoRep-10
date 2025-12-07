package main

import (
	"log"
	"net/http"

	"singularity.com/pz10-auth/internal/http"
	"singularity.com/pz10-auth/internal/platform/config"
)

func main() {
	cfg := config.Load()
	mux := router.Build(cfg) // см. следующий шаг
	log.Println("listening on", cfg.Port)
	log.Fatal(http.ListenAndServe(cfg.Port, mux))
}
