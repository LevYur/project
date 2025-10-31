package middleware

import (
	"github.com/LevYur/project/auth/pkg/constants"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {

		reqID := c.GetHeader("X-Request-ID")
		if reqID == "" {
			reqID = uuid.NewString()
		}

		c.Set(constants.RequestIDKey, reqID)

		c.Writer.Header().Set("X-Request-ID", reqID)

		c.Next()
	}
}
