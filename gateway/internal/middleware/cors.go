package middleware

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"project/gateway/pkg/constants"
)

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {

		const op = "project/gateway.middleware.Cors"

		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods",
			"GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers",
			"Authorization, Content-Type, X-Request-ID, X-CSRF-Token, "+
				"Accept, Accept-Language, Origin, Cache-Control, X-Requested-With")

		if c.Request.Method == http.MethodOptions {

			logAny, exists := c.Get(constants.LoggerKey)
			if exists {
				log := logAny.(*zap.Logger)

				log.Info("CORS preflight request",
					zap.String(constants.LogComponentKey, op),
					zap.String(constants.LogMethodKey, c.Request.Method),
					zap.String(constants.LogPathKey, c.FullPath()),
					zap.String(constants.LogIPKey, c.ClientIP()))
			}

			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
