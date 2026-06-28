package redis

import (
	"context"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"productsmodule/internal/config"
)

func New(cfg *config.Config, log *zap.Logger) *redis.Client {

	opts := &redis.Options{
		Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
		DB:       cfg.Redis.DB, // номер БД = 0
		Password: cfg.Redis.Password,

		DialTimeout:  cfg.Redis.Timeout,
		ReadTimeout:  cfg.Redis.Timeout,
		WriteTimeout: cfg.Redis.Timeout,
		PoolTimeout:  cfg.Redis.Timeout,

		MaxRetries: cfg.Redis.MaxRetries,
		PoolSize:   cfg.Redis.PoolSize,
	}

	redisClient := redis.NewClient(opts)

	err := redisClient.Ping(context.Background()).Err()
	if err != nil {
		log.Fatal("❌ redis connection failed", zap.Error(err))
	}

	log.Info("✅ Redis client is ready after ping")

	return redisClient
}
