package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
	"time"
)

type Config struct {
	Env        string `yaml:"env" env:"ENV" env-default:"local"`
	HTTPServer `yaml:"http_server"`
	Auth       `yaml:"auth"`
	Services   `yaml:"services"`
}

type HTTPServer struct {
	Address         string        `yaml:"address" env:"HTTP_SERVER_ADDRESS"`
	ShutdownTimeout time.Duration `yaml:"server_shutdown_timeout" env:"HTTP_SERVER_SHUTDOWN_TIMEOUT" env-default:"5s"`
	Timeout         time.Duration `yaml:"timeout" env:"HTTP_SERVER_TIMEOUT" env-default:"5s"`
	ReadTimeout     time.Duration `yaml:"read_timeout" env:"HTTP_SERVER_READ_TIMEOUT" env-default:"5s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" env:"HTTP_SERVER_WRITE_TIMEOUT" env-default:"10s"`
	IdleTimeout     time.Duration `yaml:"idle_timeout" env:"HTTP_SERVER_IDLE_TIMEOUT" env-default:"60s"`
}

type Auth struct {
	JWTSecret string        `yaml:"jwt_secret" env:"AUTH_JWT_SECRET"`
	TokenTTL time.Duration `yaml:"token_ttl" env:"AUTH_TOKEN_TTL"`
}

type Services struct {
	AuthServiceAddr     string `yaml:"auth_service" env:"SERVICES_AUTH_SERVICE_ADDR"`
	ProductsServiceAddr string `yaml:"products_service" env:"SERVICES_PRODUCTS_SERVICE_ADDR"`
	UsersServiceAddr    string `yaml:"users_service" env:"SERVICES_USERS_SERVICE_ADDR"`
	BasketServiceAddr   string `yaml:"basket_service" env:"SERVICES_BASKET_SERVICE_ADDR"`
	OrdersServiceAddr   string `yaml:"orders_service" env:"SERVICES_ORDERS_SERVICE_ADDR"`
	NotsServiceAddr     string `yaml:"nots_service" env:"SERVICES_NOTS_SERVICE_ADDR"`
}

func MustLoad() *Config {

	cfg := Config{}

	// try to load config from local file
	err := cleanenv.ReadConfig("./config/.env", &cfg)
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
