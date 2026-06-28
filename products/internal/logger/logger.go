package logger

import (
	"fmt"
	"go.uber.org/zap"
	"productsmodule/internal/constants"
)

func InitLogger(env string) *zap.Logger {

	const op = "cart.logger.InitLogger"

	var cfg zap.Config

	switch env {
	case constants.EnvLocal:
		cfg = zap.NewDevelopmentConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "products",
			"env":     constants.EnvLocal,
		}

	case constants.EnvDev:
		cfg = zap.NewDevelopmentConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "products",
			"env":     constants.EnvDev,
		}

	case constants.EnvProd:
		cfg = zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "products",
			"env":     constants.EnvProd,
		}
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(fmt.Sprintf("%s, %v", op, err))
	}

	return logger
}
