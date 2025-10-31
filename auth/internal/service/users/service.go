package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"project/auth/internal/broker/rabbitmq"
	errs "project/auth/internal/errors"
	"project/auth/internal/server/users"
	"project/auth/internal/service/tokens"
	"project/auth/pkg/constants"
)

type UsersRepo interface {
	IsEmailExists(ctx context.Context, email string) (bool, error)
	BeginTx(ctx context.Context) (*sqlx.Tx, error)
	CreateAuthDataTx(ctx context.Context, tx *sqlx.Tx, email, hashPass string) (int, error)
}

type OutboxRepo interface {
	AddOutboxEventTx(ctx context.Context, tx *sqlx.Tx, eventType string, payload []byte) error
	GetUnprocessedEvents(ctx context.Context) ([]users.OutboxEvent, error)
	MarkEventProcessed(ctx context.Context, id int) error
}

type Service struct {
	usersRepo    UsersRepo
	outboxRepo   OutboxRepo
	tokenManager tokens.TokenManager
	broker       rabbitmq.Publisher
}

func NewService(usersRepo UsersRepo, outboxRepo OutboxRepo,
	publisher *rabbitmq.RabbitPublisher, manager tokens.TokenManager) *Service {

	return &Service{
		usersRepo:    usersRepo,
		outboxRepo:   outboxRepo,
		tokenManager: manager,
		broker:       publisher,
	}
}

func (s *Service) Register(ctx context.Context, req users.RegisterRequest) (*users.RegisterResponse, error) {

	const op = "auth.service.users.Register"

	exists, err := s.usersRepo.IsEmailExists(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("%s: get user failed: %w", op, err)
	}
	if exists {
		return nil, errs.ErrUserAlreadyExists
	}

	hashPass, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("%s: generate hash password error: %w", op, err)
	}

	// START TRANSACTION ===============================================================

	tx, err := s.usersRepo.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to begin tx: %w", op, err)
	}

	defer func() {
		log := zap.L()
		log.Warn("rollback is running for transaction", zap.Error(err),
			zap.String(constants.LogEmailKey, req.Email),
			zap.String(constants.LogComponentKey, op))

		if err = tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Error("rollback failed", zap.Error(err),
				zap.String(constants.LogEmailKey, req.Email),
				zap.String(constants.LogComponentKey, op))
		}
	}()

	userID, err := s.usersRepo.CreateAuthDataTx(ctx, tx, req.Email, string(hashPass))
	if err != nil {
		return nil, fmt.Errorf("%s: create user failed: %w", op, err)
	}

	payload := map[string]any{
		"user_id":      userID,
		"email":        req.Email,
		"phone":        req.Phone,
		"name":         req.Name,
		"surname":      req.Surname,
		"fathers_name": req.FathersName,
		"birth_date":   req.BirthDate,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%s: marshal payload failed: %w", op, err)
	}

	err = s.outboxRepo.AddOutboxEventTx(ctx, tx, "user.created", payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: add outbox event failed: %w", op, err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("%s: commit failed: %w", op, err)
	}

	// FINISH TRANSACTION ===============================================================

	// main.RunWorkerWithGracefulShutdown - parallel worker of sending info to users-service

	accessToken, refreshToken, err := s.tokenManager.GenerateTokens(userID)
	if err != nil {
		return nil, fmt.Errorf("%s: generate tokens failed: %w", op, err)
	}

	resp := &users.RegisterResponse{
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return resp, nil
}
