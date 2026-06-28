package grpcserver

import (
	"context"
	"fmt"
	prodextv1 "github.com/LevYur/project-protos/products/external/gen/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
	"productsmodule/internal/config"
	"productsmodule/internal/constants"
	"productsmodule/internal/interceptor"
	"time"
)

type GRPCServer struct {
	grpcServer *grpc.Server
	addr       string
	timeout    time.Duration // shutdown timeout
	log        *zap.Logger
}

func New(
	cfg *config.Config, handler prodextv1.ProductsServiceServer, log *zap.Logger) *GRPCServer {

	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		interceptor.Recoverer(log),
		interceptor.Logger(log),
	))

	prodextv1.RegisterProductsServiceServer(grpcServer, handler)

	addr := fmt.Sprintf("%s:%s", cfg.GRPCServer.Host, cfg.GRPCServer.Port)

	return &GRPCServer{
		grpcServer: grpcServer,
		addr:       addr,
		timeout:    cfg.HTTPServer.ShutdownTimeout,
		log:        log,
	}
}

func (s *GRPCServer) RunWithGracefulShutdown(ctx context.Context) {

	const op = "products.server.RunWithGracefulShutdown(grpc)"

	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.log.Fatal("❌ grpc listen failed",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogAddrKey, s.addr),
		)
	}

	serverErr := make(chan error, 1)

	go func() {
		s.log.Info("✅ grpc server started", zap.String("addr", s.addr))
		serverErr <- s.grpcServer.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		s.log.Warn("❗context canceled by signal or timeout exceeded, graceful stopping...")
		s.grpcServer.GracefulStop()
		return

	case err = <-serverErr:
		if err != nil {
			s.log.Fatal("❗grpc server stopped unexpectedly",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op),
			)
		}
		s.log.Info("✅ grpc server stopped cleanly")
		return
	}
}
