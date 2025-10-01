package constants

// from environment variables
const (
	EnvLocal = "local"
	EnvDev   = "dev"
	EnvProd  = "prod"
)

// keys for gin.Context.Get
const (
	RequestIDKey = "requestID"
	LoggerKey    = "logger"
)

// keys for zap.Logger
const (
	LogRequestIDKey  = "request_id"
	LogErrorKey      = "error"
	LogMethodKey     = "method"
	LogPathKey       = "path"
	LogStatusKey     = "status"
	LogDurationKey   = "duration"
	LogComponentKey  = "component"
	LogIPKey         = "client_ip"
	LogEmailKey      = "email"
	LogURLServiceKey = "url_service"
)
