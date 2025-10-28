package server

import (
	"gateway/internal/config"
	"gateway/internal/middleware"
	"gateway/internal/server/auth"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"
	"net/http"
)

func SetupRouter(cfg *config.Config, log *zap.Logger) *gin.Engine {

	router := gin.New()

	router.Use(middleware.Recoverer(log))
	router.Use(middleware.Timeout(cfg.Timeout))
	router.Use(middleware.ValidateContentType(log))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(log))
	router.Use(middleware.Cors())
	router.Use(middleware.RateLimiter())
	router.Use(middleware.PrometheusMetrics())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(cfg, log))

	router.HandleMethodNotAllowed = true // для замены стандартных текстовых заголовков при 404

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
	})

	router.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "method not allowed"})
	})

	router.HandleMethodNotAllowed = true // turn on 405 Method Not Allowed

	api := router.Group("/api")

	api.GET("/gateway/swagger/*any", gin.WrapH(httpSwagger.WrapHandler))
	api.GET("/gateway/metrics", gin.WrapH(promhttp.Handler()))

	// auth router + handlers
	auth.RegisterRoutes(cfg, api.Group("/auth"), log)

	// products router + handlers
	// products.RegisterRoutes(api.Group("/products"), log)

	// users router + handlers
	// users.RegisterRoutes(api.Group("/users"), log)

	// создать middleware для JWT только для ручек basket и orders

	// basket router + handlers
	// basket.RegisterRoutes(api.Group("/basket"), log)

	// orders router + handlers
	// orders.RegisterRoutes(api.Group("/orders"), log)

	return router
}
