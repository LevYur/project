// @title           Gateway API
// @version         1.0
// @description     Gateway service validates and routes incoming HTTP requests,
// adds service headers and redirects them to internal microservices
// @termsOfService  http://swagger.io/terms/

// @contact.name   Lev U.
// @contact.url    https://github.com/LevYur/project.git
// @contact.email  lev.uy@mail.ru

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:7970
// @BasePath  /api/gateway/

package main

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	_ "project/gateway/docs"
	"project/gateway/internal/config"
	"project/gateway/internal/logger"
	_ "project/gateway/internal/metrics"
	"project/gateway/internal/server"
	"project/gateway/internal/validation"
	"project/gateway/pkg/constants"
)

func main() {

	validation.RegisterCustomValidators()

	cfg := config.MustLoad()

	log := logger.InitLogger(cfg.Env)
	zap.ReplaceGlobals(log)
	defer func() {
		_ = log.Sync() // сбрасывает буфер логов при завершении
	}()

	if cfg.Env == constants.EnvProd {
		gin.SetMode(gin.ReleaseMode)
	}

	router := server.SetupRouter(cfg, log)

	// run server
	gatewayServer := server.New(router, log, cfg)
	gatewayServer.RunWithGracefulShutdown()
}
