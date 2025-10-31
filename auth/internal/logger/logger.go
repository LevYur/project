package logger

import (
	"fmt"
	"go.uber.org/zap"
	"project/auth/pkg/constants"
)

func InitLogger(env string) *zap.Logger {

	const op = "auth.logger.InitLogger"

	var cfg zap.Config

	switch env {
	case constants.EnvLocal:
		cfg = zap.NewDevelopmentConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "auth",
			"env":     constants.EnvLocal,
		}

	case constants.EnvDev:
		cfg = zap.NewDevelopmentConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "auth",
			"env":     constants.EnvDev,
		}

	case constants.EnvProd:
		cfg = zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "auth",
			"env":     constants.EnvProd,
		}
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(fmt.Sprintf("%s, %v", op, err))
	}

	return logger
}
