package service

import (
	"context"
	"go.uber.org/zap"
	"productsmodule/internal/broker/kafka/producer"
	"productsmodule/internal/constants"
	"time"
)

type RepoInterface interface {
	SaveToRedis(ctx context.Context, items []Item) error
	SaveToDB(ctx context.Context, items []Item) error
	UpdateInRedis(ctx context.Context, item Item) error
	UpdateInDBPut(ctx context.Context, item Item) error
	UpdateInDBPatch(ctx context.Context, productID string, item ItemPointer) error
	DeleteFromRedis(ctx context.Context, productID string) error
	DeleteFromDB(ctx context.Context, productID string) error
	GetFromRedis(ctx context.Context, productID []string) ([]Item, []string)
	GetFromDB(ctx context.Context, productID []string) ([]Item, error)
}

type Service struct {
	repo     RepoInterface
	producer producer.ProducerInterface
	log      *zap.Logger
}

func New(repo RepoInterface, producer producer.ProducerInterface, log *zap.Logger) *Service {
	return &Service{repo: repo, producer: producer, log: log}
}

func (s *Service) AddItems(ctx context.Context, items []Item) error {

	const op = "products.service.AddItems"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = s.log
	}

	err := s.repo.SaveToDB(ctx, items)
	if err != nil {
		log.Error("❌ failed to save into DB",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))

		return err
	}

	// cache warm-up
	err = s.repo.SaveToRedis(ctx, items)
	if err != nil {
		log.Error("❗failed to save into redis",
			zap.Error(err),
			zap.String(constants.LogComponentKey, op))
	}

	return nil
}

func (s *Service) UpdateItemsPut(ctx context.Context, item Item) error {

	const op = "products.service.UpdateItemsPut"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = s.log
	}

	err := s.repo.UpdateInDBPut(ctx, item)
	if err != nil {
		log.Error("❌ failed to update in DB",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, item.ProductID),
			zap.String(constants.LogComponentKey, op))

		return err
	}

	// cache warm-up
	err = s.repo.UpdateInRedis(ctx, item)
	if err != nil {
		log.Error("❗failed to update in redis",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, item.ProductID),
			zap.String(constants.LogComponentKey, op))
	}

	go func() {

		err = s.producer.PublishProductUpdated(item.ProductID)
		if err != nil {
			log.Error("❗failed to publish message into kafka",
				zap.Error(err),
				zap.String(constants.LogProductIDKey, item.ProductID),
				zap.String(constants.LogComponentKey, op))
		}

		log.Info("👉 message was sent into kafka",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, item.ProductID),
			zap.String(constants.LogComponentKey, op))
	}()

	return nil
}

func (s *Service) UpdateItemsPatch(ctx context.Context, productID string, item ItemPointer) error {

	const op = "products.service.UpdateItemsPatch"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = s.log
	}

	err := s.repo.UpdateInDBPatch(ctx, productID, item)
	if err != nil {
		log.Error("❌ failed to update in DB",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, productID),
			zap.String(constants.LogComponentKey, op))

		return err
	}

	go func(productID string, log *zap.Logger) {

		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// get updated item
		ids := []string{productID}
		updItems, err := s.repo.GetFromDB(bgCtx, ids)
		if err != nil || len(updItems) == 0 {
			log.Warn("❗ failed to to get updated item from DB",
				zap.Error(err),
				zap.String(constants.LogProductIDKey, productID),
				zap.String(constants.LogComponentKey, op))

			return
		}

		// cache warm-up
		err = s.repo.UpdateInRedis(ctx, updItems[0])
		if err != nil {
			log.Error("❗failed to update in redis",
				zap.Error(err),
				zap.String(constants.LogProductIDKey, productID),
				zap.String(constants.LogComponentKey, op))
		}
	}(productID, log)

	go func() {
		err = s.producer.PublishProductUpdated(productID)
		if err != nil {
			log.Error("❗failed to publish message into kafka",
				zap.Error(err),
				zap.String(constants.LogProductIDKey, productID),
				zap.String(constants.LogComponentKey, op))
		}

		log.Info("👉 message was sent into kafka",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, productID),
			zap.String(constants.LogComponentKey, op))
	}()

	return nil
}

func (s *Service) DeleteItems(ctx context.Context, productID string) error {

	const op = "products.service.DeleteItems"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok || log == nil {
		log = s.log
	}

	err := s.repo.DeleteFromDB(ctx, productID)
	if err != nil {
		log.Error("❌ failed to delete from DB",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, productID),
			zap.String(constants.LogComponentKey, op))

		return err
	}

	// cache invalidate
	err = s.repo.DeleteFromRedis(ctx, productID)
	if err != nil {
		log.Error("❗failed to delete from redis",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, productID),
			zap.String(constants.LogComponentKey, op))
	}

	go func() {
		err = s.producer.PublishProductDeleted(productID)
		if err != nil {
			log.Error("❗failed to publish message into kafka",
				zap.Error(err),
				zap.String(constants.LogProductIDKey, productID),
				zap.String(constants.LogComponentKey, op))
		}

		log.Info("👉 message was sent into kafka",
			zap.Error(err),
			zap.String(constants.LogProductIDKey, productID),
			zap.String(constants.LogComponentKey, op))
	}()

	return nil
}

func (s *Service) GetItems(ctx context.Context, ids []string) ([]Item, error) {

	const op = "products.service.GetItems"

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
		_ = s.repo.SaveToRedis(ctx, dbItems)

		foundItems = append(foundItems, dbItems...)
	}

	return foundItems, nil
}
