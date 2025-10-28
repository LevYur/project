package server

import (
	"auth/internal/config"
	"auth/pkg/constants"
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
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

func (s *Server) RunWithGracefulShutdown(ctx context.Context) {

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	serverErr := make(chan error, 1)

	go func() {
		serverErr <- s.MustRun()
	}()

	select {
	case <-ctx.Done(): // завершение по сигналу
		s.Stop(shutdownCtx)
	case <-serverErr:
		s.Stop(shutdownCtx)
	}
}

func (s *Server) MustRun() error {

	const op = "auth.server.MustRun"

	s.log.Info("starting server", zap.String(constants.LogAddrKey, s.httpServer.Addr))

	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {

		s.log.Error("run server error",
			zap.Error(err),
			zap.String(constants.LogAddrKey, s.httpServer.Addr),
			zap.String(constants.LogComponentKey, op),
		)

		return err
	}

	return nil
}

func (s *Server) Stop(ctx context.Context) {

	const op = "auth.server.Stop"

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
