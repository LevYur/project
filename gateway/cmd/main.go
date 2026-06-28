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
	"fmt"
	_ "gateway/docs"
	"gateway/internal/clients/cartclient"
	"gateway/internal/config"
	"gateway/internal/logger"
	_ "gateway/internal/metrics"
	"gateway/internal/server"
	"gateway/internal/validation"
	"gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
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

	cartClient := cartclient.New(
		log,
		cartclient.WithEndpoint(cfg.CartServiceGRPCAddr),
		cartclient.WithLogger(log.Named("cartclient")),
		cartclient.WithDialTimeout(cfg.DialTimeout),
		cartclient.WithRetryPolicy(fmt.Sprintf(`{
		"methodConfig": [{
			"name": [{"service": "cart.CartService"}],
			"loadBalancingConfig": [{"round_robin": {}}],
			"retryPolicy": {
				"maxAttempts": %d,
				"initialBackoff": "0.1s",
				"maxBackoff": "1s",
				"backoffMultiplier": 2,
                "retryableStatusCodes": ["UNAVAILABLE"]
			}
		}]
	}`, cfg.Retry)),
	)
	defer func() { _ = cartClient.Close() }()

	router := server.SetupRouter(cfg, cartClient, log)

	// run server
	gatewayServer := server.New(router, log, cfg)
	gatewayServer.RunWithGracefulShutdown()
}
