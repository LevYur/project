package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
	"time"
)

type Config struct {
	Env string `env:"ENV" env-default:"local"`
	HTTPServer
	GRPCServer
	HTTPServices
	Redis
	GRPCServices
	DB
	KafkaProducer
}

type HTTPServer struct {
	HTTPServerAddr  string        `env:"HTTP_SERVER_ADDRESS"`
	Timeout         time.Duration `env:"HTTP_SERVER_TIMEOUT" env-default:"5s"`
	ShutdownTimeout time.Duration `env:"HTTP_SERVER_SHUTDOWN_TIMEOUT" env-default:"5s"`
	ReadTimeout     time.Duration `env:"HTTP_SERVER_READ_TIMEOUT" env-default:"10s"`
	WriteTimeout    time.Duration `env:"HTTP_SERVER_WRITE_TIMEOUT" env-default:"10s"`
	IdleTimeout     time.Duration `env:"HTTP_SERVER_IDLE_TIMEOUT" env-default:"5s"`
}

type GRPCServer struct {
	Host            string        `env:"RPC_SERVER_HOST"`
	Port            string        `env:"RPC_SERVER_PORT"`
	Timeout         time.Duration `env:"RPC_SERVER_TIMEOUT" env-default:"5s"`
	ShutdownTimeout time.Duration `env:"RPC_SERVER_SHUTDOWN_TIMEOUT" env-default:"5s"`
	IdleTimeout     time.Duration `env:"RPC_SERVER_IDLE_TIMEOUT" env-default:"5s"`
}

type HTTPServices struct {
	GatewayHTTPAddr string `env:"HTTP_GATEWAY_SERVICE_ADDR"`
	AuthHTTPAddr    string `env:"HTTP_AUTH_SERVICE_ADDR"`
	CartHTTPAddr    string `env:"HTTP_CART_SERVICE_ADDR"`
	UsersHTTPAddr   string `env:"HTTP_USERS_SERVICE_ADDR"`
	OrdersHTTPAddr  string `env:"HTTP_ORDERS_SERVICE_ADDR"`
	NotsHTTPAddr    string `env:"HTTP_NOTS_SERVICE_ADDR"`
}

type GRPCServices struct {
	GatewayGRPCAddr string `env:"GRPC_GATEWAY_SERVICE_ADDR"`
	AuthGRPCAddr    string `env:"GRPC_AUTH_SERVICE_ADDR"`
	CartGRPCAddr    string `env:"GRPC_CART_SERVICE_ADDR"`
	UsersGRPCAddr   string `env:"GRPC_USERS_SERVICE_ADDR"`
	OrdersGRPCAddr  string `env:"GRPC_ORDERS_SERVICE_ADDR"`
	NotsGRPCAddr    string `env:"GRPC_NOTS_SERVICE_ADDR"`
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

type KafkaProducer struct {
	Brokers []string      `env:"KAFKA_BROKERS"`
	Topic   string        `env:"KAFKA_TOPIC"`
	GroupID string        `env:"KAFKA_GROUP_ID"`
	Timeout time.Duration `env:"KAFKA_PRODUCER_TIMEOUT" env-default:"5s"`
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
