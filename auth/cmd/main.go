package main

import (
	"auth/internal/config"
	"auth/internal/logger"
	"auth/internal/server"
	"auth/pkg/constants"
	"github.com/gin-gonic/gin"
)

func main() {

	cfg := config.MustLoad()

	log := logger.InitLogger(cfg.Env)
	defer func() {
		_ = log.Sync()
	}()

	if cfg.Env == constants.EnvProd {
		gin.SetMode(gin.ReleaseMode)
	}

	// repo

	// business

	// router + handlers
	router := gin.New()

	// run server
	authServer := server.New(cfg, router, log)
	authServer.RunWithGracefulShutdown()
}
