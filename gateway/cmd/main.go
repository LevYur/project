// @title           Gateway API
// @version         1.0
// @description     Gateway for user authentication and registration.
// @termsOfService  http://swagger.io/terms/

// @contact.name   Lev U.
// @contact.url    https://github.com/LevYur/project.git
// @contact.email  lev.uy@mail.ru

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:79701
// @BasePath  /
package main

import (
	_ "gateway/docs"
	"gateway/internal/config"
	"gateway/internal/logger"
	"gateway/internal/middleware"
	"gateway/internal/server"
	"gateway/internal/server/auth"
	"gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {

	cfg := config.MustLoad()

	log := logger.InitLogger(cfg.Env)
	defer func() {
		_ = log.Sync() // сбрасывает буфер логов при завершении программы
	}()

	if cfg.Env == constants.EnvProd {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	router.Use(middleware.Recoverer(log))
	router.Use(middleware.Timeout(cfg.Timeout))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(log))
	router.Use(middleware.Cors())
	router.Use(middleware.RateLimiter())
	router.Use(middleware.PrometheusMetrics())

	api := router.Group("/api")

	api.GET("/swagger/*any", gin.WrapH(httpSwagger.WrapHandler))

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

	// run server
	gatewayServer := server.New(router, log, cfg)
	gatewayServer.RunWithGracefulShutdown()
}
