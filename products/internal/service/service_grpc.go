package service

import (
	"context"
	"go.uber.org/zap"
	"productsmodule/internal/constants"
)

type ServiceForCart struct {
	repo RepoForCartInt
	log  *zap.Logger
}

type RepoForCartInt interface {
	GetFromRedis(ctx context.Context, ids []string) ([]Item, []string)
	GetFromDB(ctx context.Context, ids []string) ([]Item, error)
	SaveToRedis(ctx context.Context, items []Item) error
}

func NewServiceForCart(repo RepoForCartInt, log *zap.Logger) *ServiceForCart {
	return &ServiceForCart{repo: repo, log: log}
}

func (s *ServiceForCart) GetItemsForCart(ctx context.Context, ids []string) ([]ItemForCart, error) {

	const op = "products.service.GetItemsForCart"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = s.log
	}

	foundItems, missingIDs := s.repo.GetFromRedis(ctx, ids)
	if len(missingIDs) > 0 {

		log.Info("👉 not all of items found in redis, trying get from DB",
			zap.String(constants.LogComponentKey, op))

		// fallback to DB
		dbItems, err := s.repo.GetFromDB(ctx, missingIDs)
		if err != nil {
			return nil, err
		}

		// cache warm-up
		err = s.repo.SaveToRedis(ctx, dbItems)
		if err != nil {
			log.Warn("❗failed to warm-up redis cache", zap.Error(err))
		}

		foundItems = append(foundItems, dbItems...)
	}

	cartItems := make([]ItemForCart, len(foundItems))

	for i, item := range foundItems {
		cartItems[i].ProductID = item.ProductID
		cartItems[i].Name = item.Name
		cartItems[i].Photo = item.Media.MainPhoto
		cartItems[i].Price = item.Price
	}

	return cartItems, nil
}
