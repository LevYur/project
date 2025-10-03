package server

import (
	"auth/internal/config"
	"auth/pkg/constants"
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Server struct {
	httpServer      *http.Server
	router          *gin.Engine
	shutdownTimeout time.Duration
	log             *zap.Logger
}

func New(cfg *config.Config, router *gin.Engine, logger *zap.Logger) *Server {

	newServer := Server{
		httpServer: &http.Server{
			Addr:         cfg.Address,
			Handler:      router,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},

		router:          router,
		shutdownTimeout: cfg.ShutdownTimeout,
		log:             logger,
	}

	return &newServer
}

func (s *Server) RunWithGracefulShutdown() {

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go s.MustRun()

	<-stop

	s.Stop()
}

func (s *Server) MustRun() {

	const op = "auth.server.MustRun"

	s.log.Info("starting server", zap.String(constants.LogAddrKey, s.httpServer.Addr))

	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Fatal("run server error",
			zap.Error(err),
			zap.String(constants.LogAddrKey, s.httpServer.Addr),
			zap.String(constants.LogComponentKey, op),
		)
	}

}

func (s *Server) Stop() {

	const op = "auth.server.Stop"

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	err := s.httpServer.Shutdown(ctx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Fatal("stop server error",
			zap.Error(err),
			zap.String(constants.LogAddrKey, s.httpServer.Addr),
			zap.String(constants.LogComponentKey, op),
		)
	}

	s.log.Info("server gracefully stopped", zap.String(constants.LogAddrKey, s.httpServer.Addr))
}
