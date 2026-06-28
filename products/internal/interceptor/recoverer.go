package interceptor

import (
	"context"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"productsmodule/internal/constants"
	"runtime/debug"
)

func Recoverer(log *zap.Logger) grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp interface{}, err error) {

		defer func() {
			rec := recover()
			if rec != nil {

				log.Error("❗panic recovered",
					zap.Any(constants.LogErrorKey, rec),
					zap.ByteString("stack", debug.Stack()),
					zap.String(constants.LogMethodKey, info.FullMethod))

				err = status.Errorf(codes.Internal, "panic: %v", rec)
			}
		}()

		resp, err = handler(ctx, req)

		if err != nil {
			log.Error("❗handler returned error",
				zap.Error(err),
				zap.String("method", info.FullMethod),
				zap.ByteString("stack", debug.Stack()),
			)
		} else {
			log.Info("👉 products-service handler success",
				zap.String("method", info.FullMethod),
			)
		}

		return resp, err
	}
}
