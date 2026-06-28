package products

import (
	"cartmodule/internal/service"
	"context"
)

type Handler struct {
	productRepo service.ProductsRepoInterface
}

func NewHandler(productRepo service.ProductsRepoInterface) *Handler {
	return &Handler{productRepo: productRepo}
}

type Event struct {
	Type      string `json:"type"`
	ProductID string `json:"product_id"`
}

func (h *Handler) CacheInvalidationHandle(ctx context.Context, event Event) error {

	err := h.productRepo.DeleteProductFromRedis(ctx, event.ProductID)
	if err != nil {
		return err
	}

	return nil
}
