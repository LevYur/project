package main

import (
	"cartmodule/internal/broker/consumer/kafka/products"
	"cartmodule/internal/client/productsclient"
	"cartmodule/internal/config"
	"cartmodule/internal/constants"
	"cartmodule/internal/db/cart"
	"cartmodule/internal/handlers"
	"cartmodule/internal/logger"
	"cartmodule/internal/metrics"
	"cartmodule/internal/redis"
	"cartmodule/internal/repository"
	"cartmodule/internal/server/grpc"
	"cartmodule/internal/service"
	"context"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	cfg := config.MustLoad()

	log := logger.InitLogger(cfg.Env)
	zap.ReplaceGlobals(log)
	defer func() {
		_ = log.Sync() // сбрасывает буфер логов при завершении
	}()

	if cfg.Env == constants.EnvProd {
		gin.SetMode(gin.ReleaseMode)
	}

	// prepare context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		log.Info("Shutdown signal received")
		cancel()
	}()

	// run prometheus
	metrics.StartMetricsServer(cfg.HTTPServerAddr, log)

	// layers
	redisClient := redis.NewClient(cfg, log)
	cartDB := cart.ConnectDB(cfg, log) // + creates 'carts' table

	defer func() { _ = redisClient.Close() }()
	defer func() { _ = cartDB.Close() }()

	cartRepo := repository.NewCartRepo(cartDB, redisClient, cfg.Redis.CacheTTL)
	productRepo := repository.NewProductRepo(redisClient, cfg.Redis.CacheTTL)

	grpcProductsClient := productsclient.New(cfg, log)

	cartService := service.New(cartRepo, productRepo, grpcProductsClient)
	handler := handlers.New(cartService)

	// run kafka
	kafkaDecoder := products.NewDecoder()
	kafkaHandler := products.NewHandler(productRepo)

	kafkaConsumer := products.NewConsumer(
		log,
		cfg.Brokers,
		cfg.Topic,
		cfg.GroupID,
		kafkaHandler,
		kafkaDecoder,
	)

	go kafkaConsumer.MustRun(ctx)

	// run server
	addr := cfg.GRPCServer.Host + ":" + cfg.GRPCServer.Port
	grpcServer := grpc.New(addr, handler, log)
	grpcServer.RunWithGracefulShutdown(ctx)
}
