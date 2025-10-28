package constants

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

// keys for context.Context
type ctxKey string

const LoggerCtxKey ctxKey = "logger"

// keys for zap.Logger
const (
	LogComponentKey   = "component"
	LogAddrKey        = "address"
	LogIPKey          = "client_ip"
	LogEmailKey       = "email"
	LogUserIDKey      = "user_id"
	LogURLServiceKey  = "url_service"
	LogRequestIDKey   = "request_id"
	LogErrorKey       = "error"
	LogMethodKey      = "method"
	LogPathKey        = "path"
	LogStatusKey      = "status"
	LogDurationKey    = "duration"
	LogRequestBodyKey = "request_body"
)
