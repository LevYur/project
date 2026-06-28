package handlers

import (
	"cartmodule/internal/constants"
	"cartmodule/internal/errs"
	"cartmodule/internal/metrics"
	"cartmodule/internal/model"
	"context"
	"errors"
	cartextv1 "github.com/LevYur/project-protos/cart/external/gen.v1"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

type CartServiceInterface interface {
	AddToCart(ctx context.Context, UserId int, ProductId string, Quantity int) error
	RemoveFromCart(ctx context.Context, UserId int, ProductId string) error
	ClearCart(ctx context.Context, UserId int) error
	GetCart(ctx context.Context, UserId int) (*model.Cart, error)
}

type CartHandler struct {
	cartextv1.UnimplementedCartServiceServer
	service CartServiceInterface
}

func New(srv CartServiceInterface) *CartHandler {
	return &CartHandler{service: srv}
}

func (h *CartHandler) AddToCart(ctx context.Context, req *cartextv1.AddToCartRequest) (
	*cartextv1.CartBoolResponse, error) {

	start := time.Now()

	const op = "cart.handlers.AddToCart"
	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok {
		log = zap.NewNop()
	}

	err := h.service.AddToCart(ctx, int(req.UserId), req.ProductId, int(req.Quantity))
	if err != nil {

		log.Error("failed to add product to cart",
			zap.String(constants.LogComponentKey, op),
			zap.Error(err),
			zap.Int64(constants.LogUserIDKey, req.UserId),
			zap.String(constants.LogProductIDKey, req.ProductId),
		)

		metrics.CartAddTotal.WithLabelValues("AddToCart", "error").Inc() // prometheus

		switch {
		case errors.Is(err, errs.ErrInvalidRequest):
			return nil, status.Errorf(codes.InvalidArgument, "failed to add to cart: %v", err)

		default:
			return nil, status.Errorf(codes.Internal, "failed to add to cart: %v", err)
		}
	}

	log.Info("product added to cart successfully",
		zap.String(constants.LogComponentKey, op),
		zap.Int64(constants.LogUserIDKey, req.UserId),
		zap.String(constants.LogProductIDKey, req.ProductId),
	)

	// prometheus
	metrics.CartAddTotal.WithLabelValues("AddToCart", "ok").Inc()
	metrics.HandlerDuration.WithLabelValues("AddToCart").Observe(time.Since(start).Seconds())

	return &cartextv1.CartBoolResponse{Success: true}, nil
}

func (h *CartHandler) RemoveFromCart(ctx context.Context, req *cartextv1.RemoveFromCartRequest) (
	*cartextv1.CartBoolResponse, error) {

	start := time.Now()

	const op = "cart.handlers.RemoveFromCart"
	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok {
		log = zap.NewNop()
	}

	err := h.service.RemoveFromCart(ctx, int(req.UserId), req.ProductId)
	if err != nil {
		log.Error("failed to remove product from cart",
			zap.String(constants.LogComponentKey, op),
			zap.Error(err),
			zap.Int64(constants.LogUserIDKey, req.UserId),
			zap.String(constants.LogProductIDKey, req.ProductId),
		)

		metrics.CartRemoveTotal.WithLabelValues("RemoveFromCart", "error").Inc() // prometheus
		return nil, status.Errorf(codes.Internal, "failed to remove from cart: %v", err)
	}

	log.Info("product removed from cart successfully",
		zap.String(constants.LogComponentKey, op),
		zap.Int64(constants.LogUserIDKey, req.UserId),
		zap.String(constants.LogProductIDKey, req.ProductId),
	)

	// prometheus
	metrics.CartRemoveTotal.WithLabelValues("RemoveFromCart", "ok").Inc()
	metrics.HandlerDuration.WithLabelValues("RemoveFromCart").Observe(time.Since(start).Seconds())

	return &cartextv1.CartBoolResponse{Success: true}, nil
}

func (h *CartHandler) ClearCart(ctx context.Context, req *cartextv1.ClearCartRequest) (
	*cartextv1.CartBoolResponse, error) {

	start := time.Now()

	const op = "cart.handlers.ClearCart"
	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok {
		log = zap.NewNop()
	}

	err := h.service.ClearCart(ctx, int(req.UserId))
	if err != nil {
		log.Error("failed to clear cart",
			zap.String(constants.LogComponentKey, op),
			zap.Error(err),
			zap.Int64(constants.LogUserIDKey, req.UserId),
		)

		metrics.CartClearTotal.WithLabelValues("ClearCart", "error") // prometheus
		return nil, status.Errorf(codes.Internal, "failed to clear cart: %v", err)
	}

	log.Info("cart cleared successfully",
		zap.String(constants.LogComponentKey, op),
		zap.Int64(constants.LogUserIDKey, req.UserId),
	)

	// prometheus
	metrics.CartClearTotal.WithLabelValues("ClearCart", "ok")
	metrics.HandlerDuration.WithLabelValues("ClearCart").Observe(time.Since(start).Seconds())

	return &cartextv1.CartBoolResponse{Success: true}, nil
}

func (h *CartHandler) GetCart(ctx context.Context, req *cartextv1.GetCartRequest) (
	*cartextv1.GetCartResponse, error) {

	start := time.Now()

	const op = "cart.handlers.GetCart"
	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok {
		log = zap.NewNop()
	}

	cart, err := h.service.GetCart(ctx, int(req.UserId))
	if err != nil {
		log.Error("failed to receive product list and total price",
			zap.String(constants.LogComponentKey, op),
			zap.Error(err),
			zap.Int64(constants.LogUserIDKey, req.UserId),
		)

		metrics.CartGetTotal.WithLabelValues("GetCart", "error") // prometheus

		return nil, status.Errorf(
			codes.Internal, "failed to receive product list and total price: %v", err)
	}

	items := make([]*cartextv1.CartItem, len(cart.Items))
	for i, item := range cart.Items {
		items[i] = &cartextv1.CartItem{
			ProductId: item.ProductID,
			Name:      item.Name,
			Photo:     item.Photo,
			Price:     item.Price,
			Quantity:  int32(item.Quantity),
		}
	}

	log.Info("product list and total price receive successfully",
		zap.String(constants.LogComponentKey, op),
		zap.Int64(constants.LogUserIDKey, req.UserId),
	)

	// prometheus
	metrics.CartGetTotal.WithLabelValues("GetCart", "ok")
	metrics.HandlerDuration.WithLabelValues("GetCart").Observe(time.Since(start).Seconds())

	return &cartextv1.GetCartResponse{Items: items, TotalPrice: cart.TotalPrice}, nil
}
