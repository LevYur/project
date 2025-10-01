package auth

import (
	"bytes"
	"encoding/json"
	"gateway/internal/config"
	"gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
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

//func (h *Handler) Login(c *gin.Context) {
//	// пока заглушка, без похода в другой сервис
//	c.JSON(http.StatusOK, gin.H{
//		"message": "login: все четко!",
//	})
//}
//

// Login godoc
// @Summary User login
// Authenticate user and return access & refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param        loginRequest  body      LoginRequest  true  "Login credentials"
// @Success      200  {object}  LoginResponse
// @Failure      400  {object}  map[string]string  "Invalid request"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Router       /auth/login [post]
func (h *Handler) Login(c *gin.Context) {

	const op = "internal.server.auth.Login"

	log := h.log                                 // base logger
	logAny, exists := c.Get(constants.LoggerKey) // enriched logger if exists
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	if c.Request.Method != http.MethodPost {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
		return
	}

	var req LoginRequest

	// + email and pass validation
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error("invalid login request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)
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
	authReq, err := http.NewRequestWithContext(
		ctx, http.MethodPost, h.nextServiceURL, bytes.NewBuffer(body))

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

	resp, err := h.client.Do(authReq) // client with business-logic context
	if err != nil {
		log.Error("send request error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	defer resp.Body.Close()

	log.Info("auth service response",
		zap.String(constants.LogComponentKey, op),
		zap.Int("status", resp.StatusCode),
		zap.String(constants.LogMethodKey, http.MethodPost),
		zap.String(constants.LogURLServiceKey, h.nextServiceURL),
	)

	switch {
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})

	case resp.StatusCode >= 500:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	default:
		c.DataFromReader(resp.StatusCode, resp.ContentLength,
			resp.Header.Get("Content-Type"), resp.Body, nil)
	}
}

// Register godoc
// @Summary User register
// Authenticate user and return access & refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param        registerRequest  body      RegisterRequest  true  "Register credentials"
// @Success      200  {object}  RegisterResponse
// @Failure      400  {object}  map[string]string  "Invalid request"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Router       /auth/register [post]
func (h *Handler) Register(c *gin.Context) {

	const op = "internal.server.auth.Register"

	log := h.log
	logAny, exist := c.Get(constants.LoggerKey)
	if exist {
		log = logAny.(*zap.Logger)
	}

	var req RegisterRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Error("unmarshall error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)
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
	authReq, err := http.NewRequestWithContext(
		ctx, http.MethodPost, h.nextServiceURL, bytes.NewBuffer(body))

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
		log.Error("send request error",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	defer resp.Body.Close()

	log.Info("auth service response",
		zap.String(constants.LogComponentKey, op),
		zap.Int("status", resp.StatusCode),
		zap.String(constants.LogMethodKey, http.MethodPost),
		zap.String(constants.LogURLServiceKey, h.nextServiceURL),
	)

	switch {
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})

	case resp.StatusCode >= 500:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	default:
		c.DataFromReader(200, -1, resp.Header.Get("Content-Type"),
			bytes.NewBuffer([]byte("register: все четко!")), nil)

		//c.DataFromReader(resp.StatusCode, resp.ContentLength,
		//	resp.Header.Get("Content-Type"), resp.Body, nil)
	}

}
