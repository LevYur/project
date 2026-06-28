package cart

import (
	"context"
	"gateway/internal/metrics"
	"gateway/pkg/constants"
	cartextv1 "github.com/LevYur/project-protos/cart/external/gen.v1"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
)

type ClientInterface interface {
	AddToCart(ctx context.Context, req *cartextv1.AddToCartRequest) (*cartextv1.CartBoolResponse, error)
	RemoveFromCart(ctx context.Context, req *cartextv1.RemoveFromCartRequest) (*cartextv1.CartBoolResponse, error)
	ClearCart(ctx context.Context, req *cartextv1.ClearCartRequest) (*cartextv1.CartBoolResponse, error)
	GetCart(ctx context.Context, req *cartextv1.GetCartRequest) (*cartextv1.GetCartResponse, error)
}

type Handler struct {
	cartClient ClientInterface
	log        *zap.Logger
}

func NewHandler(client ClientInterface, logger *zap.Logger) *Handler {

	return &Handler{
		cartClient: client,
		log:        logger,
	}
}

func RegisterRoutes(client ClientInterface, rg *gin.RouterGroup, log *zap.Logger) {

	handler := NewHandler(client, log)

	rg.POST("/add", handler.AddToCart)                       // /api/cart/add
	rg.DELETE("/delete/:product_id", handler.RemoveFromCart) // /api/cart/delete/:product_id
	rg.DELETE("", handler.ClearCart)                         // /api/cart
	rg.GET("", handler.GetCart)                              // /api/cart
}

// AddToCart godoc
// @Summary Add item to user's cart
// @Description Add item to user's cart by product ID + quantity
// @Tags cart
// @Accept json
// @Produce json
// @Param request body AddToCartRequest true "Add to cart payload"
// @Success 200 {object} map[string]bool "success: true"
// @Failure 400 "Invalid request"
// @Failure 401 "Unauthorized"
// @Failure 403 "Permission denied"
// @Failure 404 "Not found"
// @Failure 408 "Timeout"
// @Failure 503 "Service unavailable"
// @Failure 500 "Internal error"
// @Router /cart/add [post]
func (h *Handler) AddToCart(c *gin.Context) {

	// prometheus
	timer := prometheus.NewTimer(metrics.GRPCRequestDuration.WithLabelValues("cart", "AddToCart"))
	defer timer.ObserveDuration()

	const op = "gateway.server.cart.AddToCart"

	log := h.log                                 // base logger
	logAny, exists := c.Get(constants.LoggerKey) // enriched logger if exists
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	var req AddToCartRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error("❌ invalid request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
		)

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userIDValue, exists := c.Get(constants.UserIDKey)
	if !exists {
		log.Error("❌ failed to get user id from gin.Context",
			zap.String(constants.LogComponentKey, op),
		)

		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := int64((userIDValue).(int))

	ctx := c.Request.Context()

	log.Info("👉 calling AddToCart remote procedure (gRPC) ")

	resp, err := h.cartClient.AddToCart(ctx, &cartextv1.AddToCartRequest{
		UserId:    userID,
		ProductId: req.ProductID,
		Quantity:  int32(req.Quantity),
	})

	if err != nil {
		metrics.GPRCRequestsTotal.WithLabelValues("cart", "AddToCart", "error") // prometheus
		grpcToHTTPError(c, log, err)
		return
	}

	if !resp.Success {
		log.Error("❌ unexpected response from cart-service: success=false",
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	metrics.GPRCRequestsTotal.WithLabelValues("cart", "AddToCart", "ok") // prometheus
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// RemoveFromCart godoc
// @Summary Remove item from user's cart
// @Description Remove item from user's cart by product ID. Removes all quantity of that item
// @Tags cart
// @Accept json
// @Produce json
// @Param product_id path int true "Product ID to remove"
// @Success 200 {object} map[string]bool "success: true"
// @Failure 400 "Invalid request"
// @Failure 401 "Unauthorized"
// @Failure 403 "Permission denied"
// @Failure 404 "Not found"
// @Failure 408 "Timeout"
// @Failure 503 "Service unavailable"
// @Failure 500 "Internal error"
// @Router /cart/delete/{product_id} [delete]
func (h *Handler) RemoveFromCart(c *gin.Context) {

	// prometheus
	timer := prometheus.NewTimer(metrics.GRPCRequestDuration.WithLabelValues("cart", "RemoveFromCart"))
	defer timer.ObserveDuration()

	const op = "gateway.server.cart.RemoveFromCart"

	log := h.log                                 // base logger
	logAny, exists := c.Get(constants.LoggerKey) // enriched logger if exists
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	productID := c.Param("product_id")
	if productID == "" {
		log.Error("invalid request: missing product_id",
			zap.String(constants.LogComponentKey, op),
		)

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userIDValue, exists := c.Get(constants.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := int64((userIDValue).(int))

	ctx := c.Request.Context()

	resp, err := h.cartClient.RemoveFromCart(ctx, &cartextv1.RemoveFromCartRequest{
		UserId:    userID,
		ProductId: productID,
	})

	if err != nil {
		metrics.GPRCRequestsTotal.WithLabelValues("cart", "RemoveFromCart", "error") // prometheus
		grpcToHTTPError(c, log, err)
		return
	}

	if !resp.Success {
		log.Error("unexpected response from cart-service: success=false",
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	metrics.GPRCRequestsTotal.WithLabelValues("cart", "RemoveFromCart", "ok") // prometheus
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ClearCart godoc
// @Summary Clear all items from user's cart
// @Description Clear all items from user's cart by user ID
// @Tags cart
// @Accept json
// @Produce json
// @Success 200 {object} map[string]bool "success: true"
// @Failure 400 "Invalid request"
// @Failure 401 "Unauthorized"
// @Failure 403 "Permission denied"
// @Failure 404 "Not found"
// @Failure 408 "Timeout"
// @Failure 503 "Service unavailable"
// @Failure 500 "Internal error"
// @Router /cart [delete]
func (h *Handler) ClearCart(c *gin.Context) {

	// prometheus
	timer := prometheus.NewTimer(metrics.GRPCRequestDuration.WithLabelValues("cart", "ClearCart"))
	defer timer.ObserveDuration()

	const op = "gateway.server.cart.ClearCart"

	log := h.log                                 // base logger
	logAny, exists := c.Get(constants.LoggerKey) // enriched logger if exists
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	userIDValue, exists := c.Get(constants.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := int64((userIDValue).(int))

	ctx := c.Request.Context()

	resp, err := h.cartClient.ClearCart(ctx, &cartextv1.ClearCartRequest{UserId: userID})
	if err != nil {
		metrics.GPRCRequestsTotal.WithLabelValues("cart", "ClearCart", "error") // prometheus
		grpcToHTTPError(c, log, err)
		return
	}

	if !resp.Success {
		log.Error("unexpected response from cart-service: success=false",
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	metrics.GPRCRequestsTotal.WithLabelValues("cart", "ClearCart", "ok") // prometheus
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// GetCart godoc
// @Summary Get all items from user's cart
// @Description Get all items from user's cart by user ID
// @Tags cart
// @Accept json
// @Produce json
// @Success 200 {string} GetCartResponse
// @Failure 400 "Invalid request"
// @Failure 401 "Unauthorized"
// @Failure 403 "Permission denied"
// @Failure 404 "Not found"
// @Failure 408 "Timeout"
// @Failure 503 "Service unavailable"
// @Failure 500 "Internal error"
// @Router /cart [get]
func (h *Handler) GetCart(c *gin.Context) {

	// prometheus
	timer := prometheus.NewTimer(metrics.GRPCRequestDuration.WithLabelValues("cart", "GetCart"))
	defer timer.ObserveDuration()

	const op = "gateway.server.cart.AddToCart"

	log := h.log                                 // base logger
	logAny, exists := c.Get(constants.LoggerKey) // enriched logger if exists
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	userIDValue, exists := c.Get(constants.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := int64((userIDValue).(int))

	ctx := c.Request.Context()

	resp, err := h.cartClient.GetCart(ctx, &cartextv1.GetCartRequest{
		UserId: userID,
	})

	if err != nil {
		metrics.GPRCRequestsTotal.WithLabelValues("cart", "GetCart", "error") // prometheus
		grpcToHTTPError(c, log, err)
		return
	}

	items := make([]CartItem, 0, len(resp.GetItems()))

	for _, item := range resp.GetItems() {
		items = append(items, CartItem{
			ProductID: item.GetProductId(),
			Name:      item.GetName(),
			Price:     item.GetPrice(),
			Photo:     item.GetPhoto(),
			Quantity:  int(item.GetQuantity()),
		})
	}

	metrics.GPRCRequestsTotal.WithLabelValues("cart", "GetCart", "ok") // prometheus

	c.JSON(http.StatusOK, GetCartResponse{
		UserID:     int(userID),
		Items:      items,
		TotalPrice: resp.GetTotalPrice(),
	})
}

func grpcToHTTPError(c *gin.Context, log *zap.Logger, err error) {

	const op = "gateway.server.cart.grpcToHTTPError"

	st, ok := status.FromError(err)
	if !ok {
		log.Error("cart-service response without status",
			zap.String(constants.LogComponentKey, op),
			zap.Error(err))

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	log.Error("cart-service response",
		zap.String(constants.LogComponentKey, op),
		zap.String(constants.LogStatusKey, st.Code().String()),
		zap.String(constants.LogMessageKey, st.Message()),
		zap.String(constants.LogMethodKey, http.MethodPost),
	)

	switch st.Code() {

	case codes.NotFound:
		c.JSON(http.StatusNotFound, gin.H{"error": st.Message()})

	case codes.InvalidArgument:
		c.JSON(http.StatusBadRequest, gin.H{"error": st.Message()})

	case codes.Unauthenticated:
		c.JSON(http.StatusUnauthorized, gin.H{"error": st.Message()})

	case codes.PermissionDenied:
		c.JSON(http.StatusForbidden, gin.H{"error": st.Message()})

	case codes.Unavailable:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "service unavailable"})

	case codes.DeadlineExceeded:
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "timeout calling cart service"})

	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": st.Message()})
	}
}
