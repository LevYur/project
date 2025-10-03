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
}
type HTTPServer struct {
	Address         string        `env:"HTTP_SERVER_ADDRESS"`
	Timeout         time.Duration `env:"HTTP_SERVER_TIMEOUT" env-default:"5s"`
	ShutdownTimeout time.Duration `env:"HTTP_SERVER_SHUTDOWN_TIMEOUT" env-default:"5s"`
	ReadTimeout     time.Duration `env:"HTTP_SERVER_READ_TIMEOUT" env-default:"10s"`
	WriteTimeout    time.Duration `env:"HTTP_SERVER_WRITE_TIMEOUT" env-default:"10s"`
	IdleTimeout     time.Duration `env:"HTTP_SERVER_IDLE_TIMEOUT" env-default:"5s"`
}

type Auth struct {
	JWTSecret string        `env:"AUTH_JWT_SECRET"`
	TokenTTL  time.Duration `env:"AUTH_TOKEN_TTL" env-default:"1h"`
}

type Services struct {
	AuthServiceAddr     string `env:"SERVICES_AUTH_SERVICE_ADDR"`
	ProductsServiceAddr string `env:"SERVICES_PRODUCTS_SERVICE_ADDR"`
	UsersServiceAddr    string `env:"SERVICES_USERS_SERVICE_ADDR"`
	BasketServiceAddr   string `env:"SERVICES_BASKET_SERVICE_ADDR"`
	OrdersServiceAddr   string `env:"SERVICES_ORDERS_SERVICE_ADDR"`
	NotsServiceAddr     string `env:"SERVICES_NOTS_SERVICE_ADDR"`
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
