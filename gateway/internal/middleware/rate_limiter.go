package middleware

import (
	"gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"net/http"
	"sync"
)

var visitors = make(map[string]*rate.Limiter)
var mtx sync.Mutex

func RateLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {

		ip := c.ClientIP()
		limiter := getVisitor(ip)

		if !limiter.Allow() {

			logAny, exists := c.Get("logger")
			if exists {
				log := logAny.(*zap.Logger)

				log.Warn("Rate limit exceeded",
					zap.String(constants.LogIPKey, ip),
					zap.String(constants.LogPathKey, c.FullPath()),
					zap.String(constants.LogMethodKey, c.Request.Method))
			}

			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many requests",
			})
			return
		}
	}
}

func getVisitor(ip string) *rate.Limiter {

	mtx.Lock()
	defer mtx.Unlock()

	limiter, exists := visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(2, 10)
		visitors[ip] = limiter
	}

	return limiter
}
