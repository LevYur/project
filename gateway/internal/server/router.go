package server

import (
	"gateway/internal/clients/cartclient"
	"gateway/internal/config"
	"gateway/internal/middleware"
	"gateway/internal/server/auth"
	"gateway/internal/server/cart"
	"gateway/internal/server/products"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"
	"net/http"
)

func SetupRouter(cfg *config.Config, cartClient *cartclient.CartClient, log *zap.Logger) *gin.Engine {

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

	// utility routes
	api.GET("/gateway/swagger/*any", gin.WrapH(httpSwagger.WrapHandler))
	api.GET("/gateway/metrics", gin.WrapH(promhttp.Handler()))

	// routes
	auth.RegisterRoutes(cfg, api.Group("/auth"), log)
	products.RegisterRoutes(cfg, api.Group("/products"), log)
	// users.RegisterRoutes(api.Group("/users"), log)
	cart.RegisterRoutes(cartClient, api.Group("/cart"), log)
	// orders.RegisterRoutes(api.Group("/orders"), log)

	return router
}
