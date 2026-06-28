package redis

import (
	"context"
	"github.com/redis/go-redis/v9"
	"log"
	"net"
)

type LoggingHook struct{}

func (h *LoggingHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		log.Printf("Redis Dial → %s %s", network, addr)
		return next(ctx, network, addr)
	}
}

func (h *LoggingHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		log.Printf("Redis command → %s", cmd.String())
		return next(ctx, cmd)
	}
}

func (h *LoggingHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			log.Printf("Redis pipeline command → %s", cmd.String())
		}
		return next(ctx, cmds)
	}
}
