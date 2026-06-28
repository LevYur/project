package handler

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"productsmodule/internal/constants"
	"productsmodule/internal/errs"
	"productsmodule/internal/service"
	"strings"
)

type Handler struct {
	service ServiceInterface
	log     *zap.Logger
}

type ServiceInterface interface {
	AddItems(ctx context.Context, items []service.Item) error
	UpdateItemsPut(ctx context.Context, items service.Item) error
	UpdateItemsPatch(ctx context.Context, productID string, items service.ItemPointer) error
	DeleteItems(ctx context.Context, id string) error
	GetItems(ctx context.Context, ids []string) ([]service.Item, error)
}

func New(service ServiceInterface, log *zap.Logger) *Handler {
	return &Handler{
		service: service,
		log:     log,
	}
}

// SWAGGER
func (h *Handler) AddItems(c *gin.Context) {

	const op = "products.handler.AddItems"

	ctx := c.Request.Context()
	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = h.log
	}

	var items []service.Item
	err := c.ShouldBindJSON(&items)
	if err != nil {
		log.Error("❌ failed to unmarshall",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	err = h.service.AddItems(ctx, items)
	if err != nil {
		log.Error("❌ failed to add items",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	log.Info("✅ items added successfully",
		zap.String(constants.LogComponentKey, op))

	c.JSON(http.StatusOK, gin.H{"success": "true"})
}

// SWAGGER
func (h *Handler) UpdateItemsPut(c *gin.Context) {

	const op = "products.handler.UpdateItemsPut"

	ctx := c.Request.Context()
	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = h.log
	}

	var item service.Item
	err := c.ShouldBindJSON(&item)
	if err != nil {
		log.Error("❌ failed to unmarshall",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	productID := c.Param("product_id")
	if productID == "" {
		log.Error("❌ missing product_id",
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	item.ProductID = productID

	err = h.service.UpdateItemsPut(ctx, item)
	if err != nil {
		log.Error("❌ failed to update (put) item",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, productID),
			zap.String(constants.LogComponentKey, op))

		if errors.Is(err, errs.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	log.Info("✅ item updated successfully",
		zap.String(constants.LogProductIDKey, productID),
		zap.String(constants.LogComponentKey, op))

	c.JSON(http.StatusOK, gin.H{"success": "true"})
}

// SWAGGER
func (h *Handler) UpdateItemsPatch(c *gin.Context) {

	const op = "products.handler.UpdateItemsPatch"

	ctx := c.Request.Context()
	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = h.log
	}

	productID := c.Param("product_id")
	if productID == "" {
		log.Error("❌ missing product_id",
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	var item service.ItemPointer
	err := c.ShouldBindJSON(&item)
	if err != nil {
		log.Error("❌ failed to unmarshall",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogProductIDKey, productID))

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	if item.IsEmpty() {
		log.Error("❌ empty body",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogProductIDKey, productID))

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	err = h.service.UpdateItemsPatch(ctx, productID, item)
	if err != nil {
		log.Error("❌ failed to update (patch) item",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op),
			zap.String(constants.LogProductIDKey, productID))

		if errors.Is(err, errs.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	log.Info("✅ item updated successfully",
		zap.String(constants.LogProductIDKey, productID),
		zap.String(constants.LogComponentKey, op))

	c.JSON(http.StatusOK, gin.H{"success": "true"})
}

// SWAGGER
func (h *Handler) DeleteItems(c *gin.Context) {

	const op = "products.handler.DeleteItems"

	ctx := c.Request.Context()
	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = h.log
	}

	productID := c.Param("product_id")
	if productID == "" {
		log.Error("❌ missing product_id",
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	err := h.service.DeleteItems(ctx, productID)
	if err != nil {
		log.Error("❌ failed to delete item",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, productID),
			zap.String(constants.LogComponentKey, op))

		if errors.Is(err, errs.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	log.Info("✅ item deleted successfully",
		zap.String(constants.LogProductIDKey, productID),
		zap.String(constants.LogComponentKey, op))

	c.JSON(http.StatusOK, gin.H{"success": "true"})
}

// SWAGGER
func (h *Handler) GetItems(c *gin.Context) {

	const op = "products.handler.GetItems"

	ctx := c.Request.Context()
	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = h.log
	}

	var IDs []string

	switch c.Request.Method {

	// 1) GET /products/:product_id
	case http.MethodGet:
		productID := c.Param("product_id")
		if productID != "" {
			IDs = []string{productID}
			break
		}

		// 2) GET /products?ids=1,2,3
		idsQuery := c.Query("ids")
		if idsQuery != "" {
			rawIDs := strings.Split(idsQuery, ",")
			for _, id := range rawIDs {
				id = strings.TrimSpace(id)
				if id != "" {
					IDs = append(IDs, id)
				}
			}
			break
		}

		c.JSON(http.StatusBadRequest, gin.H{"error": "missing product_id or ids"})
		return

	case http.MethodPost:
		if err := c.ShouldBindJSON(&IDs); err != nil {
			log.Error("❌ failed to unmarshall batch IDs",
				zap.Error(err),
				zap.String(constants.LogComponentKey, op))
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}

	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
		return
	}

	items, err := h.service.GetItems(ctx, IDs)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		log.Error("❌ failed to get items",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	log.Info("✅ items received successfully",
		zap.String(constants.LogComponentKey, op))

	c.JSON(http.StatusOK, items)
}
