package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type loginRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	clients map[string][]time.Time
}

var defaultLoginLimiter = &loginRateLimiter{
	limit:   5,
	window:  5 * time.Minute,
	clients: make(map[string][]time.Time),
}

func RateLimitLogin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)

			if !defaultLoginLimiter.allow(ip) {
				WriteErrorJSON(w, http.StatusTooManyRequests,
					"rate_limited", "too many login attempts, try later")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (l *loginRateLimiter) allow(ip string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	attempts := l.clients[ip]

	var fresh []time.Time
	for _, t := range attempts {
		if now.Sub(t) <= l.window {
			fresh = append(fresh, t)
		}
	}

	if len(fresh) >= l.limit {
		l.clients[ip] = fresh
		return false
	}

	fresh = append(fresh, now)
	l.clients[ip] = fresh
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
