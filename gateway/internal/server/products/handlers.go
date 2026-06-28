package products

import (
	"context"
	"errors"
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

	httpClient := &http.Client{
		Timeout: cfg.Timeout, // timeout store
		Transport: &http.Transport{
			IdleConnTimeout:     cfg.IdleTimeout, // TTL idle-connection
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
		},
	}

	return &Handler{
		client:         httpClient,
		nextServiceURL: cfg.ProductsServiceAddr,
		log:            logger,
	}
}

func RegisterRoutes(cfg *config.Config, router *gin.RouterGroup, log *zap.Logger) {

	handler := NewHandler(cfg, log)

	router.POST("", handler.AddProducts)
	router.PUT("/:product_id", handler.UpdateProductPut)
	router.PATCH("/:product_id", handler.UpdateProductPatch)
	router.DELETE("/:product_id", handler.DeleteProduct)
	router.GET("/:product_id", handler.GetProducts)
	router.GET("", handler.GetProducts)
	router.POST("/batch", handler.GetProducts)
}

// SWAGGER
func (h *Handler) AddProducts(c *gin.Context) {

	const op = "gateway.handler.AddProducts"

	log := h.log
	logAny, exists := c.Get(constants.LoggerKey)
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	ctx := c.Request.Context()
	url := h.nextServiceURL + "/api/products"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, c.Request.Body)
	if err != nil {
		log.Error("❌ failed to create request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodPost),
			zap.String(constants.LogURLServiceKey, url),
		)

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {

			log.Error("❌ timeout",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op),
				zap.Any("timeout", h.client.Timeout),
			)

			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "timeout"})
			return
		}

		log.Error("❌ failed to send request",
			zap.Error(err),
			zap.String(constants.LogMethodKey, http.MethodPost),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "products-service unavailable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	log.Info("👉 request was sent to products-service",
		zap.String(constants.LogComponentKey, op),
		zap.String(constants.LogURLServiceKey, url),
	)

	// RESPONSE ======================================================

	log.Info("✅ products-service response",
		zap.String(constants.LogComponentKey, op),
		zap.Int("status", resp.StatusCode),
		zap.String(constants.LogMethodKey, http.MethodPost),
		zap.String(constants.LogURLServiceKey, url),
	)

	c.DataFromReader(resp.StatusCode, resp.ContentLength,
		resp.Header.Get("Content-Type"), resp.Body, nil)
}

// SWAGGER
func (h *Handler) UpdateProductPut(c *gin.Context) {

	const op = "gateway.handler.UpdateProductPut"

	log := h.log
	logAny, exists := c.Get(constants.LoggerKey)
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	productID := c.Param("product_id")
	if productID == "" {
		log.Error("❌ missing product_id",
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodPut),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	url := h.nextServiceURL + "/api/products/" + productID
	ctx := c.Request.Context()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, c.Request.Body)
	if err != nil {
		log.Error("❌ failed to create request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodPut),
			zap.String(constants.LogURLServiceKey, url),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {

			log.Error("❌ timeout",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op),
				zap.Any("timeout", h.client.Timeout),
			)
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "timeout"})
			return
		}

		log.Error("❌ failed to send request",
			zap.Error(err),
			zap.String(constants.LogMethodKey, http.MethodPut),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "products-service unavailable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	log.Info("👉 request was sent to products-service",
		zap.String(constants.LogComponentKey, op),
		zap.String(constants.LogURLServiceKey, url),
	)

	// RESPONSE ======================================================

	log.Info("✅ products-service response",
		zap.String(constants.LogComponentKey, op),
		zap.Int("status", resp.StatusCode),
		zap.String(constants.LogMethodKey, http.MethodPut),
		zap.String(constants.LogURLServiceKey, url),
	)

	c.DataFromReader(resp.StatusCode, resp.ContentLength,
		resp.Header.Get("Content-Type"), resp.Body, nil)
}

// SWAGGER
func (h *Handler) UpdateProductPatch(c *gin.Context) {

	const op = "gateway.handler.UpdateProductPatch"

	log := h.log
	logAny, exists := c.Get(constants.LoggerKey)
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	productID := c.Param("product_id")
	if productID == "" {
		log.Error("❌ missing product_id",
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodPatch),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	url := h.nextServiceURL + "/api/products/" + productID
	ctx := c.Request.Context()

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, c.Request.Body)
	if err != nil {
		log.Error("❌ failed to create request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodPut),
			zap.String(constants.LogURLServiceKey, url),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {

			log.Error("❌ timeout",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op),
				zap.Any("timeout", h.client.Timeout),
			)
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "timeout"})
			return
		}

		log.Error("❌ failed to send request",
			zap.Error(err),
			zap.String(constants.LogMethodKey, http.MethodPatch),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "products-service unavailable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	log.Info("👉 request was sent to products-service",
		zap.String(constants.LogComponentKey, op),
		zap.String(constants.LogURLServiceKey, url),
	)

	// RESPONSE ======================================================

	log.Info("✅ products-service response",
		zap.String(constants.LogComponentKey, op),
		zap.Int("status", resp.StatusCode),
		zap.String(constants.LogMethodKey, http.MethodPatch),
		zap.String(constants.LogURLServiceKey, url),
	)

	c.DataFromReader(resp.StatusCode, resp.ContentLength,
		resp.Header.Get("Content-Type"), resp.Body, nil)
}

// SWAGGER
func (h *Handler) DeleteProduct(c *gin.Context) {

	const op = "gateway.handler.DeleteProduct"

	log := h.log
	logAny, exists := c.Get(constants.LoggerKey)
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	productID := c.Param("product_id")
	if productID == "" {
		log.Error("❌ missing product_id",
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodDelete),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	url := h.nextServiceURL + "/api/products/" + productID
	ctx := c.Request.Context()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		log.Error("❌ failed to create request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodDelete),
			zap.String(constants.LogURLServiceKey, url),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {

			log.Error("❌ timeout",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op),
				zap.Any("timeout", h.client.Timeout),
			)
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "timeout"})
			return
		}

		log.Error("❌ failed to send request",
			zap.Error(err),
			zap.String(constants.LogMethodKey, http.MethodDelete),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "products-service unavailable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	log.Info("👉 request was sent to products-service",
		zap.String(constants.LogComponentKey, op),
		zap.String(constants.LogURLServiceKey, url),
	)

	// RESPONSE ======================================================

	log.Info("✅ products-service response",
		zap.String(constants.LogComponentKey, op),
		zap.Int("status", resp.StatusCode),
		zap.String(constants.LogMethodKey, http.MethodDelete),
		zap.String(constants.LogURLServiceKey, url),
	)

	c.DataFromReader(resp.StatusCode, resp.ContentLength,
		resp.Header.Get("Content-Type"), resp.Body, nil)
}

// SWAGGER
func (h *Handler) GetProducts(c *gin.Context) {

	const op = "gateway.handler.GetProducts"

	log := h.log
	logAny, exists := c.Get(constants.LoggerKey)
	if exists && logAny != nil {
		log = logAny.(*zap.Logger)
	}

	ctx := c.Request.Context()
	url := h.nextServiceURL + "/api/products"
	if c.Param("product_id") != "" {
		url += "/" + c.Param("product_id")

	} else if c.Query("ids") != "" {
		url = h.nextServiceURL + "?ids=" + c.Query("ids")
	}

	req, err := http.NewRequestWithContext(ctx, c.Request.Method, url, c.Request.Body)
	if err != nil {
		log.Error("❌ failed to create request",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogMethodKey, http.MethodGet),
			zap.String(constants.LogURLServiceKey, url),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	req.Header.Set("Content-Type", c.GetHeader("Content-Type"))
	req.Header.Set("Authorization", c.GetHeader("Authorization"))

	resp, err := h.client.Do(req)
	if err != nil {

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {

			log.Error("❌ timeout",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op),
				zap.Any("timeout", h.client.Timeout),
			)
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "timeout"})
			return
		}

		log.Error("❌ failed to send request",
			zap.Error(err),
			zap.String(constants.LogMethodKey, req.Method),
			zap.String(constants.LogComponentKey, op),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "products-service unavailable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	log.Info("👉 request was sent to products-service",
		zap.String(constants.LogComponentKey, op),
		zap.String(constants.LogURLServiceKey, url),
	)

	// RESPONSE ======================================================

	log.Info("✅ products-service response",
		zap.String(constants.LogComponentKey, op),
		zap.Int("status", resp.StatusCode),
		zap.String(constants.LogMethodKey, req.Method),
		zap.String(constants.LogURLServiceKey, url),
	)

	c.DataFromReader(resp.StatusCode, resp.ContentLength,
		resp.Header.Get("Content-Type"), resp.Body, nil)
}
