package cartclient

import (
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Option — функция, меняющая настройки клиента.
// Это основа pattern "functional options".
type Option func(*config)

// config — структура с настройками gRPC-клиента.
type config struct {
	endpoint      string
	dialTimeout   time.Duration
	logger        *zap.Logger
	dialOptions   []grpc.DialOption
	serviceConfig string
	tlsEnabled    bool
}

func defaultConfig() *config {
	return &config{
		endpoint:    "",
		dialTimeout: 3 * time.Second,
		logger:      zap.NewNop(),
		dialOptions: []grpc.DialOption{
			grpc.WithBlock(),
			grpc.WithInsecure(), // default: отключён TLS
		},
		serviceConfig: "",
		tlsEnabled:    false,
	}
}

func WithEndpoint(addr string) Option {
	return func(c *config) {
		c.endpoint = addr
	}
}

func WithLogger(log *zap.Logger) Option {
	return func(c *config) {
		c.logger = log
	}
}

func WithDialTimeout(d time.Duration) Option {
	return func(c *config) {
		c.dialTimeout = d
	}
}

func WithDialOption(opt grpc.DialOption) Option {
	return func(c *config) {
		c.dialOptions = append(c.dialOptions, opt)
	}
}

func WithRetryPolicy(jsonCfg string) Option {
	return func(c *config) {
		c.serviceConfig = jsonCfg
	}
}
