package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/LevYur/project/gateway/internal/config"
	"github.com/LevYur/project/gateway/internal/metrics"
	"github.com/LevYur/project/gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

type Handler struct {
	client         *http.Client
	nextServiceURL string
	log            *zap.Logger
}

func NewHandler(cfg *config.Config, logger *zap.Logger) *Handler {

	client := &http.Client{
		Timeout: cfg.Timeout, // timeout store
		Transport: &http.Transport{
			IdleConnTimeout:     cfg.IdleTimeout, // TTL idle-connection
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
		},
	}

	return &Handler{
		client:         client,
		nextServiceURL: cfg.AuthServiceAddr,
		log:            logger,
	}
}

func RegisterRoutes(cfg *config.Config, rg *gin.RouterGroup, log *zap.Logger) {

	handler := NewHandler(cfg, log)
	rg.POST("/login", handler.Login)
	rg.POST("/register", handler.Register)
}

// Login godoc
// @Summary User login
// @Description Authenticate user and return access & refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param        loginRequest  body      LoginRequest  true  "Login credentials"
// @Success      200  {object}  LoginResponse
// @Failure      400  {object}  map[string]string  "Invalid request"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Router       /auth/login [post]
func (h *Handler) Login(c *gin.Context) {

	const op = "github.com/LevYur/project/gateway.server.auth.Login"

	log := h.log                                 // base logger
	logAny, exists := c.Get(constants.LoggerKey) // enriched logger if exists
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	var req LoginRequest

	// + email and pass validation
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error("invalid login request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)

		reason := classifyValidationError(err)
		metrics.GatewayInvalidLoginRequestTotal.WithLabelValues(reason).Inc() // prometheus

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return

	}

	body, err := json.Marshal(req)
	if err != nil {
		log.Error("marshall error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	ctx := c.Request.Context()
	url := h.nextServiceURL + "/auth/login"
	authReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))

	if err != nil {
		log.Error("failed to create request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodPost),
			zap.String(constants.LogURLServiceKey, h.nextServiceURL),
		)

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	authReq.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(authReq) // client with business-logic context
	if err != nil {

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {

			log.Error("timeout",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op),
				zap.Any("timeout", h.client.Timeout),
			)

			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "timeout"})
			return
		}

		log.Error("send request error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "auth service unavailable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	log.Info("request to auth-service was sent",
		zap.String(constants.LogComponentKey, op),
		zap.String(constants.LogURLServiceKey, h.nextServiceURL),
	)

	// RESPONSE ======================================================

	log.Info("auth service response",
		zap.String(constants.LogComponentKey, op),
		zap.Int("status", resp.StatusCode),
		zap.String(constants.LogMethodKey, http.MethodPost),
		zap.String(constants.LogURLServiceKey, h.nextServiceURL),
	)

	c.DataFromReader(resp.StatusCode, resp.ContentLength,
		resp.Header.Get("Content-Type"), resp.Body, nil)
}

// Register godoc
// @Summary User register
// @Description Authenticate user and return access & refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param        registerRequest  body      RegisterRequest  true  "Register credentials"
// @Success      200  {object}  RegisterResponse
// @Failure      400  {object}  map[string]string  "Invalid request"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Router       /auth/register [post]
func (h *Handler) Register(c *gin.Context) {

	const op = "github.com/LevYur/project/gateway.server.auth.Register"

	log := h.log
	logAny, exist := c.Get(constants.LoggerKey)
	if exist {
		log = logAny.(*zap.Logger)
	}

	//if c.Request.Method != http.MethodPost {
	//	c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
	//	return
	//}

	var req RegisterRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Error("unmarshall error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)

		reason := classifyValidationError(err)
		metrics.GatewayInvalidRegisterRequestTotal.WithLabelValues(reason).Inc() // prometheus

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	body, err := json.Marshal(req)
	if err != nil {
		log.Error("marshall error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	ctx := c.Request.Context()
	url := h.nextServiceURL + "/auth/register"
	authReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))

	if err != nil {
		log.Error("prepare request error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodPost),
			zap.String(constants.LogURLServiceKey, h.nextServiceURL),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	authReq.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(authReq)
	if err != nil {

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {

			log.Error("timeout",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op),
				zap.Any("timeout", h.client.Timeout),
			)

			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "timeout"})
			return
		}

		log.Error("send request error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "auth service unavailable"})
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	log.Info("auth service response",
		zap.String(constants.LogComponentKey, op),
		zap.Int("status", resp.StatusCode),
		zap.String(constants.LogMethodKey, http.MethodPost),
		zap.String(constants.LogURLServiceKey, h.nextServiceURL),
	)

	// RETURN RESPONSE ==========================================

	c.DataFromReader(resp.StatusCode, resp.ContentLength,
		resp.Header.Get("Content-Type"), resp.Body, nil)
}

func classifyValidationError(err error) string {

	if strings.Contains(strings.ToLower(err.Error()), "email") {
		return "invalid email"
	}

	if strings.Contains(strings.ToLower(err.Error()), "password") {
		return "invalid password"
	}

	if strings.Contains(strings.ToLower(err.Error()), "password") {
		return "invalid password"
	}

	if strings.Contains(strings.ToLower(err.Error()), "phone") {
		return "invalid phone"
	}

	if strings.Contains(strings.ToLower(err.Error()), "name") {
		return "invalid name"
	}

	if strings.Contains(strings.ToLower(err.Error()), "surname") {
		return "invalid surname"
	}

	if strings.Contains(strings.ToLower(err.Error()), "fathersname") {
		return "invalid fathers name"
	}

	if strings.Contains(strings.ToLower(err.Error()), "birthdate") {
		return "invalid birth date"
	}

	return "internal"
}
