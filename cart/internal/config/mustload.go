package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
	"time"
)

type Config struct {
	Env            string `env:"ENV" env-default:"local"`
	HTTPServerAddr string `env:"HTTP_SERVER_ADDRESS"`
	GRPCServer
	Services
	GRPCServices
	GRPCClient
	Redis
	DB
	KafkaConsumer
}

type GRPCServer struct {
	Host            string        `env:"RPC_SERVER_HOST"`
	Port            string        `env:"RPC_SERVER_PORT"`
	Timeout         time.Duration `env:"RPC_SERVER_TIMEOUT" env-default:"5s"`
	ShutdownTimeout time.Duration `env:"RPC_SERVER_SHUTDOWN_TIMEOUT" env-default:"5s"`
	IdleTimeout     time.Duration `env:"RPC_SERVER_IDLE_TIMEOUT" env-default:"5s"`
}

type Services struct {
	GatewayServiceAddr  string `env:"HTTP_GATEWAY_SERVICE_ADDR"`
	AuthServiceAddr     string `env:"HTTP_AUTH_SERVICE_ADDR"`
	ProductsServiceAddr string `env:"HTTP_PRODUCTS_SERVICE_ADDR"`
	UsersServiceAddr    string `env:"HTTP_USERS_SERVICE_ADDR"`
	OrdersServiceAddr   string `env:"HTTP_ORDERS_SERVICE_ADDR"`
	NotsServiceAddr     string `env:"HTTP_NOTS_SERVICE_ADDR"`
}

type GRPCServices struct {
	GatewayServiceGRPCAddr  string `env:"GRPC_GATEWAY_SERVICE_ADDR"`
	AuthServiceGRPCAddr     string `env:"GRPC_AUTH_SERVICE_ADDR"`
	ProductsServiceGRPCAddr string `env:"GRPC_PRODUCTS_SERVICE_ADDR"`
	UsersServiceGRPCAddr    string `env:"GRPC_USERS_SERVICE_ADDR"`
	OrdersServiceGRPCAddr   string `env:"GRPC_ORDERS_SERVICE_ADDR"`
	NotsServiceGRPCAddr     string `env:"GRPC_NOTS_SERVICE_ADDR"`
}

type GRPCClient struct {
	DialTimeout  time.Duration `env:"RPC_CLIENT_DIAL_TIMEOUT" env-default:"5s"`
	RetryBackoff time.Duration `env:"RPC_CLIENT_RETRY_BACKOFF" env-default:"10s"`
}

type Redis struct {
	Host       string        `env:"REDIS_HOST"`
	Port       string        `env:"REDIS_PORT"`
	DB         int           `env:"REDIS_DB"`
	Password   string        `env:"REDIS_PASSWORD"`
	Timeout    time.Duration `env:"REDIS_TIMEOUT"`
	MaxRetries int           `env:"REDIS_MAX_RETRIES"`
	PoolSize   int           `env:"REDIS_POOL_SIZE"`
	CacheTTL   time.Duration `env:"REDIS_CACHE_TTL"`
}

type DB struct {
	User        string        `env:"POSTGRES_USER"`
	Password    string        `env:"POSTGRES_PASSWORD"`
	Host        string        `env:"POSTGRES_HOST"`
	Port        int           `env:"POSTGRES_PORT"`
	DBName      string        `env:"POSTGRES_NAME"`
	SSLMode     string        `env:"POSTGRES_SSLMODE"`
	MaxConn     int           `env:"POSTGRES_MAX_CONN"`
	ConnTimeout time.Duration `env:"POSTGRES_CONN_TIMEOUT"`
}

type KafkaConsumer struct {
	Brokers []string `env:"KAFKA_BROKERS"`
	Topic   string   `env:"KAFKA_TOPIC"`
	GroupID string   `env:"KAFKA_GROUP_ID"`
}

func MustLoad() *Config {

	var cfg Config

	// settings from env variables (from docker)
	err := cleanenv.ReadEnv(&cfg)
	if err == nil {
		log.Println("✅ loaded config from DOCKER env-variables")
		return &cfg
	}

	// try to load config from local file
	err = cleanenv.ReadConfig("./config/.env.local", &cfg)
	if err == nil {
		log.Println("✅ loaded config from local .env")
		return &cfg
	} else {
		log.Fatalf("cannot load config from environment: %v", err)
	}

	return &cfg
}
