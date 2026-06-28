package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"os"
	"os/signal"
	"productsmodule/internal/broker/kafka/producer"
	"productsmodule/internal/config"
	"productsmodule/internal/constants"
	"productsmodule/internal/db/products"
	"productsmodule/internal/handler"
	"productsmodule/internal/logger"
	"productsmodule/internal/redis"
	"productsmodule/internal/repository"
	"productsmodule/internal/server"
	"productsmodule/internal/server/grpcserver"
	"productsmodule/internal/service"
	"syscall"
)

func main() {

	cfg := config.MustLoad()

	log := logger.InitLogger(cfg.Env)
	defer func() {
		_ = log.Sync() // сбрасывает буфер логов при завершении
	}()

	if cfg.Env == constants.EnvProd {
		gin.SetMode(gin.ReleaseMode)
	}

	// products context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		log.Info("❗Shutdown signal received")
		cancel()
	}()

	// run prometheus
	// metrics.StartMetricsServer(cfg.HTTPServerAddr, log)

	// layers
	redisClient := redis.New(cfg, log)
	prodDB := products.ConnectDB(cfg, log) // + creates 'main' and 'media' tables
	defer func() { _ = redisClient.Close() }()
	defer func() { _ = prodDB.Close() }()

	prodRepo := repository.New(prodDB, redisClient, cfg.Redis.CacheTTL, log)

	// run kafka producer
	kafkaProducer := producer.New(cfg, log)
	defer kafkaProducer.Close()

	prodService := service.New(prodRepo, kafkaProducer, log)
	router := handler.SetupRoutes(prodService, cfg.HTTPServer.Timeout, log)

	// run gRPC server
	cartService := service.NewServiceForCart(prodRepo, log)
	cartHandler := handler.NewHandlerForCart(cartService, log)
	grpcServer := grpcserver.New(cfg, cartHandler, log)
	go grpcServer.RunWithGracefulShutdown(ctx)

	// run HTTP server
	httpServer := server.NewHTTPServer(cfg, router, log)
	httpServer.RunWithGracefulShutdown(ctx)
}
