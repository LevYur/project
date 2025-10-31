package server

import (
	"context"
	"errors"
	"github.com/LevYur/project/gateway/internal/config"
	"github.com/LevYur/project/gateway/pkg/constants"
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
	log             *zap.Logger
	shutdownTimeout time.Duration
}

// New - creates a new instance of server
func New(router *gin.Engine, logger *zap.Logger, cfg *config.Config) *Server {

	newServer := Server{
		router:          router,
		log:             logger,
		shutdownTimeout: cfg.ShutdownTimeout,

		httpServer: &http.Server{
			Addr:         cfg.Address,
			Handler:      router,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
	}

	return &newServer
}

func (s *Server) MustRun() {
	const op = "github.com/LevYur/project/gateway.server.MustRun"

	s.log.Info("Starting server", zap.String("address", s.httpServer.Addr))

	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {

		s.log.Fatal("Run server error", // os.Exit(1)
			zap.Error(err),
			zap.String("address", s.httpServer.Addr),
			zap.String(constants.LogComponentKey, op))
	}
}

func (s *Server) Stop() {

	const op = "github.com/LevYur/project/gateway.server.Stop"

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	err := s.httpServer.Shutdown(ctx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {

		s.log.Fatal("Graceful shutdown server stop error",
			zap.Error(err),
			zap.String("address", s.httpServer.Addr),
			zap.String(constants.LogComponentKey, op))
	}

	s.log.Info("starting server", zap.String("address", s.httpServer.Addr))
}

func (s *Server) RunWithGracefulShutdown() {

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go s.MustRun()

	<-stop

	s.Stop()
}
