package middleware

import (
	"bytes"
	"github.com/LevYur/project/auth/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"io"
	"net/http"
)

func Recoverer(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		defer func() {
			err := recover()
			if err != nil {

				bodyBytes, _ := io.ReadAll(c.Request.Body)
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // возвращаем тело обратно в поток

				log.Error("panic recovered",
					zap.Any(constants.LogErrorKey, err),
					zap.Any("stacktrace", err),
					zap.String(constants.LogPathKey, c.FullPath()),
					zap.String(constants.LogMethodKey, c.Request.Method),
					zap.ByteString(constants.LogRequestBodyKey, bodyBytes))

				c.AbortWithStatusJSON(http.StatusInternalServerError,
					gin.H{"error": "internal server error"})
			}
		}()

		c.Next()
	}
}
