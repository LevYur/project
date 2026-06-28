package middleware

import (
	"context"
	"gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {

		reqID := c.GetHeader("X-Request-ID")
		if reqID == "" {
			reqID = uuid.NewString()
		}

		c.Set(constants.RequestIDKey, reqID) // add into gin.Context

		ctx := context.WithValue(c.Request.Context(), constants.CtxRequestIDKey, reqID)
		c.Request = c.Request.WithContext(ctx) // add into context.Context

		c.Writer.Header().Set("X-Request-ID", reqID) // add into Header

		c.Next()
	}
}
