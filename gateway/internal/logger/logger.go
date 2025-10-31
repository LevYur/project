package logger

import (
	"fmt"
	"github.com/LevYur/project/gateway/pkg/constants"
	"go.uber.org/zap"
)

// InitLogger creates logger instance based on "env" from env. variables
func InitLogger(env string) *zap.Logger {

	const op = "github.com/LevYur/project/gateway.logger.InitLogger"

	var cfg zap.Config

	switch env {
	case constants.EnvLocal:
		cfg = zap.NewDevelopmentConfig() // text + stdout
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "github.com/LevYur/project/gateway",
			"env":     constants.EnvLocal,
		}

	case constants.EnvDev:
		cfg = zap.NewDevelopmentConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "github.com/LevYur/project/gateway",
			"env":     constants.EnvDev,
		}

	case constants.EnvProd:
		cfg = zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "github.com/LevYur/project/gateway",
			"env":     constants.EnvProd,
		}

	default:
		cfg = zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		cfg.InitialFields = map[string]interface{}{
			"service": "github.com/LevYur/project/gateway",
			"env":     constants.EnvProd,
		}
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(fmt.Sprintf("%s, %v", op, err))
	}

	return logger
}
