package middleware

import (
	"encoding/json"
	"net/http"
)

type errorResponse struct {
	Error   string      `json:"error"`
	Details interface{} `json:"details,omitempty"`
}

func WriteErrorJSON(w http.ResponseWriter, code int, msg string, details ...interface{}) {
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
