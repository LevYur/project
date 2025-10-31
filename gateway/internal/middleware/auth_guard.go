package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/LevYur/project/gateway/internal/config"
	"github.com/LevYur/project/gateway/internal/metrics"
	"github.com/LevYur/project/gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

var privatePaths = map[string]struct{}{
	"/api/auth/refresh": {},
}

func AuthGuard(cfg *config.Config, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		const op = "github.com/LevYur/project/gateway.middleware.AuthGuard"

		logAny, exist := c.Get(constants.LoggerKey)
		if exist {
			log = logAny.(*zap.Logger)
		}

		path := c.Request.URL.Path
		_, ok := privatePaths[path]
		if !ok {
			c.Next()
			return
		}

		accessToken := extractAccessToken(c.Request)
		if accessToken == "" {

			log.Warn("access token is empty",
				zap.String(constants.LogComponentKey, op),
				zap.String(constants.LogMethodKey, c.Request.Method),
				zap.String(constants.LogPathKey, c.FullPath()),
				zap.String(constants.LogIPKey, c.ClientIP()))

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		// just for access token, not refresh
		err := validateAccessToken(cfg, accessToken, "access")
		if err == nil {
			c.Next() // if token valid

			return
		}

		if err != nil {
			log.Warn("access token is invalid",
				zap.String(constants.LogComponentKey, op),
				zap.Error(err),
				zap.String(constants.LogMethodKey, c.Request.Method),
				zap.String(constants.LogPathKey, c.FullPath()),
				zap.String(constants.LogIPKey, c.ClientIP()))
		}

		refreshToken, err := c.Cookie("refresh_token")
		if err != nil || refreshToken == "" {

			log.Warn("missing or empty refresh token",
				zap.String(constants.LogComponentKey, op),
				zap.Error(err),
				zap.String(constants.LogMethodKey, c.Request.Method),
				zap.String(constants.LogPathKey, c.FullPath()),
				zap.String(constants.LogIPKey, c.ClientIP()))

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		ctx := c.Request.Context()

		gatewayHTTPClient := &http.Client{
			Timeout: cfg.Timeout, // timeout store
			Transport: &http.Transport{
				IdleConnTimeout:     cfg.IdleTimeout, // TTL idle-connection
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
			},
		}

		newTokens, err := callRefreshEndpoint(ctx, refreshToken, cfg, gatewayHTTPClient, log)
		if err != nil {

			reason := classifyRefreshError(err)
			metrics.AuthRefreshFailedTotal.WithLabelValues(reason).Inc() // prometheus

			if errors.Is(err, context.DeadlineExceeded) {

				log.Error("timeout",
					zap.Error(err),
					zap.String(constants.LogComponentKey, op),
					zap.Any("timeout", gatewayHTTPClient.Timeout),
				)

				c.AbortWithStatusJSON(http.StatusGatewayTimeout, gin.H{"error": "timeout"})
				return
			}

			log.Warn("error: send refresh token to auth-service",
				zap.String(constants.LogComponentKey, op),
				zap.Error(err),
				zap.String(constants.LogMethodKey, c.Request.Method),
				zap.String(constants.LogPathKey, c.FullPath()),
				zap.String(constants.LogIPKey, c.ClientIP()))

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		// SETTING NEW TOKENS ==========================================================

		metrics.AuthRefreshSuccessTotal.Inc() // prometheus

		c.Request.Header.Set("Authorization", "Bearer "+newTokens.AccessToken)

		secureFlag := cfg.Env == constants.EnvProd

		c.SetCookie("refresh_token", newTokens.RefreshToken,
			int(cfg.RefreshTokenTTL.Seconds()), "/", "", secureFlag, true)

		c.SetSameSite(http.SameSiteNoneMode)

		log.Info("access token refreshed",
			zap.String(constants.LogPathKey, c.FullPath()),
			zap.String(constants.LogIPKey, c.ClientIP()),
			zap.Int(constants.LogUserIDKey, newTokens.UserID),
		)

		c.Next()
	}
}

func extractAccessToken(req *http.Request) string {

	header := req.Header.Get("Authorization")
	if header == "" {
		return ""
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

func validateAccessToken(cfg *config.Config, token string, tokenType string) error {

	tokenInfo, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(tokenInfo *jwt.Token) (any, error) {

		_, ok := tokenInfo.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tokenInfo.Header["alg"])
		}

		return []byte(cfg.JWTSecret), nil
	})

	if err != nil {
		return err
	}

	if !tokenInfo.Valid {
		return fmt.Errorf("token invalid or expired: %w", err)
	}

	claims, ok := tokenInfo.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	if claims["type"] != tokenType {
		return fmt.Errorf("token type mismatch")
	}

	return nil
}

func callRefreshEndpoint(ctx context.Context, refreshToken string,
	cfg *config.Config, client *http.Client, log *zap.Logger) (*Tokens, error) {

	const op = "github.com/LevYur/project/gateway.middleware.AuthGuard.callRefreshEndpoint"

	reqBody := map[string]string{
		"refresh_token": refreshToken,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {

		log.Error("marshal refresh-token error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		return nil, fmt.Errorf("failed to marshal refresh request: %w", err)
	}

	url := cfg.AuthServiceAddr + "/auth/refresh"
	authReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	authReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(authReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// AFTER AUTH-RESPONSE =========================================================

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed with code %d", resp.StatusCode)
	}

	var tokens Tokens
	if err = json.NewDecoder(resp.Body).Decode(&tokens); err != nil {

		log.Error("error: unmarshal tokens from auth-service",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		return nil, err
	}

	return &tokens, nil
}

func classifyRefreshError(err error) string {

	if strings.Contains(err.Error(), "invalid") {
		return "invalid"
	}

	if strings.Contains(err.Error(), "expired") {
		return "expired"
	}

	if strings.Contains(err.Error(), "not_found") {
		return "not_found"
	}

	if strings.Contains(err.Error(), "timeout") {
		return "timeout"
	}

	return "internal"
}
