package middleware

import (
	"context"
	"github.com/gin-gonic/gin"
	"time"
)

// Timeout - middleware which add business logic timeout from config into context
func Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {

		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}
