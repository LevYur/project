package middleware

import (
	"github.com/LevYur/project/gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"runtime/debug"
)

func Recoverer(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		defer func() {
			err := recover()
			if err != nil {

				log.Error("panic recovered",
					zap.Any(constants.LogErrorKey, err),
					zap.ByteString("stacktrace", debug.Stack()),
					zap.String(constants.LogPathKey, c.Request.URL.Path),
					zap.String(constants.LogMethodKey, c.Request.Method),
				)

				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "internal server error",
				})
			}
		}()

		c.Next()
	}
}
