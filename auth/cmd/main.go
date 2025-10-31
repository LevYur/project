// @title           Auth API
// @version         1.0
// @description     Auth-service returns the JWT for authorization or after registration
// and transmits user data to the users microservice database via a message broker.
// @termsOfService  http://swagger.io/terms/

// @contact.name    Lev U.
// @contact.url     https://github.com/LevYur/project.git
// @contact.email   lev.uy@mail.ru

// @license.name    Apache 2.0
// @license.url     http://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath      /api

package main

import (
	"context"
	_ "github.com/LevYur/project/auth/docs"
	"github.com/LevYur/project/auth/internal/broker/rabbitmq"
	"github.com/LevYur/project/auth/internal/config"
	"github.com/LevYur/project/auth/internal/logger"
	"github.com/LevYur/project/auth/internal/middleware"
	authrepo "github.com/LevYur/project/auth/internal/repository/auth"
	usersrepo "github.com/LevYur/project/auth/internal/repository/users"
	"github.com/LevYur/project/auth/internal/server"
	"github.com/LevYur/project/auth/internal/service/auth"
	"github.com/LevYur/project/auth/internal/service/tokens"
	"github.com/LevYur/project/auth/internal/service/users"
	authdb "github.com/LevYur/project/auth/internal/storage/auth"
	"github.com/LevYur/project/auth/internal/validation"
	"github.com/LevYur/project/auth/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {

	validation.RegisterCustomValidators()

	cfg := config.MustLoad()

	log := logger.InitLogger(cfg.Env)
	zap.ReplaceGlobals(log)
	defer func() {
		_ = log.Sync()
	}()

	if cfg.Env == constants.EnvProd {
		gin.SetMode(gin.ReleaseMode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	router := gin.New()

	router.Use(middleware.Recoverer(log))
	router.Use(middleware.Timeout(cfg.Timeout))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(log))
	router.Use(middleware.PrometheusMetrics())

	db := authdb.MustConnectDB(cfg, log)

	authRepo := authrepo.NewRepository(db)
	usersRepo := usersrepo.NewRepository(db)
	outboxRepo := usersrepo.NewRepository(db)

	tokenManager := tokens.NewManager(cfg)

	authService := auth.NewService(authRepo, tokenManager)

	url := "amqp://guest:guest@rabbitmq-service:5672/"
	broker := rabbitmq.MustNewRabbitMQ(url, "users.created")
	publisher := rabbitmq.NewRabbitPublisher(broker)
	usersService := users.NewService(usersRepo, outboxRepo, publisher, tokenManager)

	router = server.AddAuthRoutes(router, authService)
	router = server.AddUsersRoutes(router, usersService)

	// run server
	authServer := server.New(cfg, router, log)
	go authServer.RunWithGracefulShutdown(ctx)

	// parallel worker of sending info to users-service
	go usersService.RunOutboxWorker(ctx)

	<-stop
	log.Info("⚠️ shutdown signal received")

	cancel()

	time.Sleep(3 * time.Second)

	log.Info("✅ graceful shutdown complete")
}
