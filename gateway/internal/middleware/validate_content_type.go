package middleware

import (
	"github.com/LevYur/project/gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
)

func ValidateContentType(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		const op = "github.com/LevYur/project/gateway.middleware.ValidateContentType"

		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodOptions ||
			c.Request.Method == http.MethodHead {

			c.Next()
			return
		}

		contentType := c.Request.Header.Get("Content-Type")
		if contentType != "application/json" {

			log.Error("request header Content-Type is not application/json",
				zap.String(constants.LogComponentKey, op))

			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "invalid request",
			})
			return
		}

		c.Next()
	}
}
