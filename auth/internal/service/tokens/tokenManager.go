package tokens

import (
	"fmt"
	"github.com/LevYur/project/auth/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"strconv"
	"time"
)

type TokenManager struct {
	jwtSecret       string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewManager(cfg *config.Config) TokenManager {

	return TokenManager{
		jwtSecret:       cfg.JWTSecret,
		accessTokenTTL:  cfg.AccessTokenTTL,
		refreshTokenTTL: cfg.RefreshTokenTTL,
	}
}

func (m *TokenManager) GenerateTokens(userID int) (accessToken, refreshToken string, err error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  strconv.Itoa(userID),
		"type": "access",
		"exp":  time.Now().Add(m.accessTokenTTL).Unix(),
	})

	accessToken, err = token.SignedString([]byte(m.jwtSecret))
	if err != nil {
		return "", "", err
	}

	token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  strconv.Itoa(userID),
		"type": "refresh",
		"exp":  time.Now().Add(m.refreshTokenTTL).Unix(),
	})

	refreshToken, err = token.SignedString([]byte(m.jwtSecret))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (m *TokenManager) ParseToken(token string) (userID int, err error) {

	if token == "" {
		return -1, fmt.Errorf("token is empty")
	}

	claims := jwt.MapClaims{}

	_, err = jwt.ParseWithClaims(token, &claims, func(tokenInfo *jwt.Token) (any, error) {

		_, ok := tokenInfo.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tokenInfo.Header["alg"])
		}

		return []byte(m.jwtSecret), nil
	})

	if err != nil {
		return -1, fmt.Errorf("failed to parse token: %w", err)
	}

	// parsing UserID
	switch id := claims["sub"].(type) {
	case float64:
		userID = int(id)
	case string:
		userID, err = strconv.Atoi(id)
		if err != nil {
			return -1, fmt.Errorf("invalid token userID string: %w", err)
		}
	default:
		return -1, fmt.Errorf("invalid token userID type: %T", id)
	}

	if userID < 1 {
		return -1, fmt.Errorf("invalid token userID")
	}

	return userID, nil
}

func (m *TokenManager) ValidateToken(token string, expectedType string) error {

	if token == "" {
		return fmt.Errorf("token is empty")
	}

	tokenInfo, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(tokenInfo *jwt.Token) (any, error) {

		_, ok := tokenInfo.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return false, fmt.Errorf("unexpected signing method: %v", tokenInfo.Header["alg"])
		}

		return []byte(m.jwtSecret), nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if !tokenInfo.Valid {
		return fmt.Errorf("token expiration is invalid")
	}

	claims, ok := tokenInfo.Claims.(jwt.MapClaims)
	if !ok {
		//log.Printf("⚠️ cannot cast token claims to MapClaims")
		return fmt.Errorf("invalid claims")
	}
	//
	//log.Printf("🧩 token claims: sub = %v, type = %s, exp = %v",
	//	claims["sub"], claims["type"], claims["exp"])

	t, ok := claims["type"].(string)
	if !ok || t != expectedType {
		return fmt.Errorf("token type is invalid")
	}

	// parsing UserID
	var userID int

	switch id := claims["sub"].(type) {
	case float64:
		userID = int(id)
	case string:
		userID, err = strconv.Atoi(id)
		if err != nil {
			return fmt.Errorf("invalid token userID string: %w", err)
		}
	default:
		return fmt.Errorf("invalid token userID type: %T", id)
	}

	if userID < 1 {
		return fmt.Errorf("invalid token userID")
	}

	return nil
}
