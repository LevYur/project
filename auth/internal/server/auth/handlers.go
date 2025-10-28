package auth

import (
	errs "auth/internal/errors"
	"auth/internal/metrics"
	"auth/pkg/constants"
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
)

type AuthService interface {
	Login(ctx context.Context, email, pass string) (*LoginResponse, error)
	Refresh(refreshToken string) (*RefreshResponse, error)
}

type Handler struct {
	authService AuthService
}

func NewHandler(service AuthService) *Handler {
	return &Handler{authService: service}
}

// Login godoc
// @Summary User login
// @Description Authenticate user with email and password. Returns access and refresh tokens on success.
// @Tags auth
// @Accept json
// @Produce json
// @Param        loginRequest  body      LoginRequest  true  "Login credentials"
// @Success      200  {object}  LoginResponse
// @Failure      400  {object}  map[string]string  "invalid request payload"
// @Failure      401  {object}  map[string]string  "invalid email or password"
// @Failure      404  {object}  map[string]string  "user not found"
// @Failure      500  {object}  map[string]string  "internal server error"
// @Router       /auth/login [post]
func (h *Handler) Login(c *gin.Context) {

	const op = "auth.server.auth.Login"

	ctx := c.Request.Context()
	log, ok := ctx.Value(constants.LoggerKey).(*zap.Logger)
	if !ok {
		log = zap.L() // fallback without context
	}

	log.Info("receive request from gateway-service",
		zap.String(constants.LogComponentKey, op))

	var req LoginRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Error("invalid request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
		})
		return
	}

	resp, err := h.authService.Login(ctx, req.Email, req.Password)
	if err != nil {

		log.Error("login failed",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		switch {
		case errors.Is(err, errs.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
			metrics.AuthLoginFailedTotal.WithLabelValues("invalid_credentials").Inc() //prometheus

		case errors.Is(err, errs.ErrUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			metrics.AuthLoginFailedTotal.WithLabelValues("not_found").Inc() //prometheus

		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_server_error"})
			metrics.AuthLoginFailedTotal.WithLabelValues("internal").Inc() //prometheus
		}
		return
	}

	c.JSON(http.StatusOK, resp)

	log.Info("login success, return response to gateway-service",
		zap.String(constants.LogComponentKey, op))

	metrics.AuthLoginSuccessTotal.Inc() //prometheus
}

// Refresh godoc
// @Summary Refresh tokens
// @Description Exchange a valid refresh token for a new pair of access and refresh tokens.
// @Tags auth
// @Accept json
// @Produce json
// @Param        RefreshRequest  body      RefreshRequest  true  "Refresh token payload"
// @Success      200  {object}  RefreshResponse
// @Failure      400  {object}  map[string]string  "invalid request"
// @Failure      401  {object}  map[string]string  "invalid or expired refresh token"
// @Failure      500  {object}  map[string]string  "internal server error"
// @Router       /auth/refresh [post]
func (h *Handler) Refresh(c *gin.Context) {

	const op = "auth.server.auth.Refresh"

	ctx := c.Request.Context()
	log, ok := ctx.Value(constants.LoggerKey).(*zap.Logger)
	if !ok {
		log = zap.L() // fallback without context
	}

	log.Info("receive request from gateway-service",
		zap.String(constants.LogComponentKey, op))

	var req RefreshRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Error("invalid request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	log.Info("🔍 incoming refresh request",
		zap.String("refresh_token", req.RefreshToken))

	resp, err := h.authService.Refresh(req.RefreshToken)
	if err != nil {

		log.Error("refresh failed",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)

		switch {
		case errors.Is(err, errs.ErrValidationToken):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
			metrics.AuthRefreshFailedTotal.WithLabelValues("invalid_token").Inc() //prometheus

		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			metrics.AuthRefreshFailedTotal.WithLabelValues("internal").Inc() //prometheus
		}
		return
	}

	c.JSON(http.StatusOK, resp)

	log.Info("refresh success, return response to gateway-service",
		zap.Int(constants.LogUserIDKey, resp.UserID),
		zap.String(constants.LogComponentKey, op))

	metrics.AuthRefreshSuccessTotal.Inc() //prometheus
}
