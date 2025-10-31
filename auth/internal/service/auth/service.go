package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	errs "project/auth/internal/errors"
	"project/auth/internal/server/auth"
	"project/auth/internal/service/tokens"
)

type AuthRepo interface {
	GetByEmail(ctx context.Context, email string) (*auth.User, error)
}

type Service struct {
	repo         AuthRepo
	tokenManager tokens.TokenManager
}

func NewService(repo AuthRepo, manager tokens.TokenManager) *Service {
	return &Service{
		repo:         repo,
		tokenManager: manager,
	}
}

func (s *Service) Login(ctx context.Context, email, pass string) (*auth.LoginResponse, error) {

	const op = "auth.service.auth.Login"

	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			return nil, fmt.Errorf("%s: %w", op, errs.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.HashPass), []byte(pass))
	if err != nil {
		return nil, errs.ErrInvalidCredentials
	}

	accessToken, refreshToken, err := s.tokenManager.GenerateTokens(user.UserID)
	if err != nil {
		return nil, fmt.Errorf("%s: generate tokens failed: %w", op, err)
	}

	resp := &auth.LoginResponse{
		UserID:       user.UserID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return resp, nil
}

func (s *Service) Refresh(refreshToken string) (*auth.RefreshResponse, error) {

	const op = "auth.service.auth.Refresh"

	err := s.tokenManager.ValidateToken(refreshToken, "refresh")
	if err != nil {

		// TODO: потом удалить этот блок
		log.Printf("[refresh] validation failed: %v", err)

		return nil, errs.ErrValidationToken
	}

	userID, err := s.tokenManager.ParseToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid refresh token: %w", op, err)
	}

	// При logout, смене пароля или компрометации токена нужно
	// иметь возможность отозвать refresh-токен досрочно
	// TODO: проверка refresh-токена в Redis/DB — живой он или отозван.

	accessToken, refreshToken, err := s.tokenManager.GenerateTokens(userID)
	if err != nil {
		return nil, fmt.Errorf("%s: generate tokens failed: %w", op, err)
	}

	resp := &auth.RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
	}

	return resp, nil
}
