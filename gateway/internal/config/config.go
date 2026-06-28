package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
	"time"
)

type Config struct {
	Env string `env:"ENV" env-default:"local"`
	HTTPServer
	Auth
	Services
	GRPCServices
	GRPCServer
}

type HTTPServer struct {
	Address         string        `env:"HTTP_SERVER_ADDRESS"`
	ShutdownTimeout time.Duration `env:"HTTP_SERVER_SHUTDOWN_TIMEOUT" env-default:"5s"`
	Timeout         time.Duration `env:"HTTP_SERVER_TIMEOUT" env-default:"5s"`
	ReadTimeout     time.Duration `env:"HTTP_SERVER_READ_TIMEOUT" env-default:"5s"`
	WriteTimeout    time.Duration `env:"HTTP_SERVER_WRITE_TIMEOUT" env-default:"10s"`
	IdleTimeout     time.Duration `env:"HTTP_SERVER_IDLE_TIMEOUT" env-default:"60s"`
}

type Auth struct {
	JWTSecret       string        `env:"JWT_SECRET"`
	AccessTokenTTL  time.Duration `env:"ACCESS_TOKEN_TTL" env-default:"30m"`
	RefreshTokenTTL time.Duration `env:"ACCESS_TOKEN_TTL" env-default:"168h"`
}

type Services struct {
	AuthServiceAddr     string `env:"HTTP_AUTH_SERVICE_ADDR"`
	ProductsServiceAddr string `env:"HTTP_PRODUCTS_SERVICE_ADDR"`
	UsersServiceAddr    string `env:"HTTP_USERS_SERVICE_ADDR"`
	CartServiceAddr     string `env:"HTTP_CART_SERVICE_ADDR"`
	OrdersServiceAddr   string `env:"HTTP_ORDERS_SERVICE_ADDR"`
	NotsServiceAddr     string `env:"HTTP_NOTS_SERVICE_ADDR"`
}

type GRPCServices struct {
	AuthServiceGRPCAddr     string `env:"RPC_AUTH_SERVICE_ADDR"`
	ProductsServiceGRPCAddr string `env:"RPC_PRODUCTS_SERVICE_ADDR"`
	UsersServiceGRPCAddr    string `env:"RPC_USERS_SERVICE_ADDR"`
	CartServiceGRPCAddr     string `env:"RPC_CART_SERVICE_ADDR"`
	OrdersServiceGRPCAddr   string `env:"RPC_ORDERS_SERVICE_ADDR"`
	NotsServiceGRPCAddr     string `env:"RPC_NOTS_SERVICE_ADDR"`
}

type GRPCServer struct {
	DialTimeout time.Duration `env:"RPC_DIAL_TIMEOUT" env-default:"3s"`
	Retry       int           `env:"RPC_RETRY" env-default:"3"`
}

func MustLoad() *Config {

	// settings from local file
	var cfg Config

	// try to load config from local file
	err := cleanenv.ReadConfig("./config/.env.local", &cfg)
	if err == nil {
		log.Println("✅ loaded config from local .env")
		return &cfg
	} else {
		log.Println("local config not found, trying environment variables...")
	}

	// settings from env variables (from docker)
	err = cleanenv.ReadEnv(&cfg)
	if err != nil {
		log.Fatalf("cannot load config from environment: %v", err)
	}

	log.Println("✅ config loaded from environment")

	return &cfg
}
