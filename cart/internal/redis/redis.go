package redis

import (
	"cartmodule/internal/config"
	"context"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func NewClient(cfg *config.Config, log *zap.Logger) *redis.Client {

	opts := &redis.Options{
		Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
		DB:       cfg.Redis.DB, // номер БД = 0
		Password: cfg.Redis.Password,

		// таймауты
		DialTimeout:  cfg.Redis.Timeout,
		ReadTimeout:  cfg.Redis.Timeout,
		WriteTimeout: cfg.Redis.Timeout,
		PoolTimeout:  cfg.Redis.Timeout,

		// параметры пула
		MaxRetries: cfg.Redis.MaxRetries,
		PoolSize:   cfg.Redis.PoolSize,
	}

	redisClient := redis.NewClient(opts)
	redisClient.AddHook(&LoggingHook{}) // logging

	err := redisClient.Ping(context.Background()).Err()
	if err != nil {
		log.Fatal("❌ Redis connection failed", zap.Error(err))
	}

	log.Info("✅ Redis client is ready after ping")

	return redisClient
}
