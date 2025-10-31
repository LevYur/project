package users

import (
	"context"
	"errors"
	errs "github.com/LevYur/project/auth/internal/errors"
	"github.com/LevYur/project/auth/internal/metrics"
	"github.com/LevYur/project/auth/pkg/constants"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
)

type UsersService interface {
	Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)
}

type Handler struct {
	usersService UsersService
}

func NewHandler(service UsersService) *Handler {
	return &Handler{usersService: service}
}

// Register godoc
// @Summary User register
// @Description Register a new user with email, password, and name.
// Returns authentication tokens on success.
// @Tags auth
// @Accept json
// @Produce json
// @Param        registerRequest  body      RegisterRequest  true  "Register credentials"
// @Success      200  {object}  RegisterResponse
// @Failure      400  {object}  map[string]string  "invalid request"
// @Failure      409  {object}  map[string]string  "user already registered"
// @Failure      500  {object}  map[string]string  "internal server error"
// @Router       /auth/register [post]
func (h *Handler) Register(c *gin.Context) {

	const op = "auth.server.users.Register"

	ctx := c.Request.Context()
	log, ok := ctx.Value(constants.LoggerKey).(*zap.Logger)
	if !ok {
		log = zap.L()
	}

	log.Info("receive request from gateway-service",
		zap.String(constants.LogComponentKey, op))

	var req RegisterRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Error("invalid request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	resp, err := h.usersService.Register(ctx, req)
	if err != nil {

		log.Warn("register failed",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogEmailKey, req.Email))

		if errors.Is(err, errs.ErrUserAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{"error": "user already registered"})
			metrics.AuthRegisterFailedTotal.WithLabelValues("already_exists").Inc() //prometheus
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		metrics.AuthRegisterFailedTotal.WithLabelValues("internal").Inc() //prometheus
		return
	}

	c.JSON(http.StatusOK, resp) // 201 better

	log.Info("register success, return response to gateway-service",
		zap.String(constants.LogComponentKey, op))

	metrics.AuthRegisterSuccessTotal.Inc() //prometheus
}
