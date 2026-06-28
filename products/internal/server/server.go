package server

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"productsmodule/internal/config"
	"productsmodule/internal/constants"
	"time"
)

type Server struct {
	httpServer      *http.Server
	router          *gin.Engine
	log             *zap.Logger
	shutdownTimeout time.Duration
}

func NewHTTPServer(
	cfg *config.Config, router *gin.Engine, log *zap.Logger) *Server {

	httpServer := &http.Server{
		Addr:         cfg.HTTPServerAddr,
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	return &Server{
		httpServer:      httpServer,
		router:          router,
		log:             log,
		shutdownTimeout: cfg.HTTPServer.ShutdownTimeout,
	}
}

func (s *Server) MustRun() {
	const op = "products.server.MustRun"

	s.log.Info("👉 Starting server", zap.String("address", s.httpServer.Addr))

	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {

		s.log.Fatal("❌ run http server error", // os.Exit(1)
			zap.Error(err),
			zap.String("address", s.httpServer.Addr),
			zap.String(constants.LogComponentKey, op))
	}
}

func (s *Server) RunWithGracefulShutdown(ctx context.Context) {
	const op = "products.server.RunWithGracefulShutdown(http)"

	go s.MustRun()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
		defer cancel()

		err := s.httpServer.Shutdown(shutdownCtx)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {

			s.log.Fatal("❌ graceful shutdown stop server error",
				zap.Error(err),
				zap.String("address", s.httpServer.Addr),
				zap.String(constants.LogComponentKey, op))
		}

		s.log.Info("✅ http server was stopped gracefully",
			zap.String("address", s.httpServer.Addr))
	}
}
