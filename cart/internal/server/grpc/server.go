package grpc

import (
	"cartmodule/internal/constants"
	"cartmodule/internal/interceptor"
	"context"
	cartextv1 "github.com/LevYur/project-protos/cart/external/gen.v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
)

type Server struct {
	srv  *grpc.Server
	addr string
	log  *zap.Logger
}

func New(addr string, handler cartextv1.CartServiceServer, log *zap.Logger) *Server {

	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		interceptor.Recoverer(log),
		interceptor.Logger(log),
	))

	cartextv1.RegisterCartServiceServer(grpcServer, handler)

	return &Server{srv: grpcServer, addr: addr, log: log}
}

func (s *Server) RunWithGracefulShutdown(ctx context.Context) {

	const op = "cart.server.grpc.RunWithGracefulShutdown"

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
		serverErr <- s.srv.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		s.log.Warn("❗context canceled by signal or timeout exceeded, graceful stopping..")
		s.srv.GracefulStop()
		return

	case err = <-serverErr:
		if err != nil {
			s.log.Fatal("❌ grpc server stopped unexpectedly",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op),
			)
		}
		s.log.Info("✅ grpc server stopped cleanly")
		return
	}
}
