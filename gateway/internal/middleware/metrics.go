package middleware

import (
	"fmt"
	"gateway/internal/metrics"
	"github.com/gin-gonic/gin"
	"time"
)

// PrometheusMetrics - send metrics into Prometheus
func PrometheusMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {

		path := c.FullPath()
		method := c.Request.Method
		start := time.Now()

		c.Next() // обрабатываем запрос

		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", c.Writer.Status())

		metrics.HttpRequestsTotal.WithLabelValues(method, path, status).Inc()
		metrics.HttpRequestDuration.WithLabelValues(method, path).Observe(duration)
	}
}
