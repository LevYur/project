package middleware

import (
	"gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"time"
)

// Logger - logging useful info about request and response
func Logger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		start := time.Now()

		reqID, ok := c.Get(constants.RequestIDKey)

		// instance of logger for every request
		if ok {
			everyRequestLogger := log.With(zap.String(constants.LogRequestIDKey, reqID.(string)))
			c.Set(constants.LoggerKey, everyRequestLogger)
		}

		c.Next()

		// After request processing
		duration := time.Since(start)
		status := c.Writer.Status()

		log.Info("request completed",
			zap.String(constants.LogMethodKey, c.Request.Method),
			zap.String(constants.LogPathKey, c.FullPath()),
			zap.Int(constants.LogStatusKey, status),
			zap.Duration(constants.LogDurationKey, duration),
		)
	}
}
