package interceptor

import (
	"cartmodule/internal/constants"
	"context"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"time"
)

// Logger - logging useful info about request and response
func Logger(log *zap.Logger) grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {

		start := time.Now()

		reqID, ok := ctx.Value(constants.RequestIDKey).(string)

		// add enriched logger into context.Context
		if ok {
			log = log.With(zap.String(constants.LogRequestIDKey, reqID))
			ctx = context.WithValue(ctx, constants.LoggerCtxKey, log)
		}

		resp, err = handler(ctx, req)

		// After request processing
		duration := time.Since(start)

		code := status.Code(err)

		log.Info("gRPC request completed",
			zap.String(constants.LogMethodKey, info.FullMethod),
			zap.String(constants.LogStatusKey, code.String()),
			zap.Duration(constants.LogDurationKey, duration),
		)

		return resp, err
	}
}
