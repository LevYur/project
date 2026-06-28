package handler

import (
	"context"
	prodextv1 "github.com/LevYur/project-protos/products/external/gen/v1"
	"go.uber.org/zap"
	"productsmodule/internal/constants"
	"productsmodule/internal/service"
)

type HandlerForCart struct {
	service ServiceForCartInt
	prodextv1.UnimplementedProductsServiceServer
	log *zap.Logger
}

type ServiceForCartInt interface {
	GetItemsForCart(ctx context.Context, ids []string) ([]service.ItemForCart, error)
}

func NewHandlerForCart(service ServiceForCartInt, log *zap.Logger) *HandlerForCart {
	return &HandlerForCart{service: service, log: log}
}

// InfoForCart calling by products service
func (h *HandlerForCart) InfoForCart(ctx context.Context, req *prodextv1.CartInfoRequest) (
	*prodextv1.CartInfoResponse, error) {

	const op = "products.handler.InfoForCart"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = h.log
	}

	items, err := h.service.GetItemsForCart(ctx, req.Ids)
	if err != nil {
		log.Error("❌ failed to get items",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		return nil, err
	}

	protoItems := make([]*prodextv1.CartItem, len(items))
	for i, item := range items {
		protoItems[i] = &prodextv1.CartItem{
			ProductId: item.ProductID,
			Name:      item.Name,
			Photo:     item.Photo,
			Price:     item.Price,
		}
	}

	return &prodextv1.CartInfoResponse{Items: protoItems}, nil
}
