package service

import (
	"cartmodule/internal/constants"
	"cartmodule/internal/errs"
	"cartmodule/internal/metrics"
	"cartmodule/internal/model"
	"context"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type CartRepoInterface interface {
	GetCartFromRedis(ctx context.Context, userID int) (*model.Cart, error)
	GetCartFromDB(ctx context.Context, userID int) (*model.Cart, error)
	SaveCartToRedis(ctx context.Context, cart *model.Cart) error
	SaveCartToDB(ctx context.Context, cart *model.Cart) error
	ClearCartInRedis(ctx context.Context, userID int) error
	ClearCartInDB(ctx context.Context, userID int) error
}

type ProductsRepoInterface interface {
	GetProductFromRedis(ctx context.Context, productID string) (*model.CartItem, error)
	SaveProductToRedis(ctx context.Context, product *model.CartItem) error
	DeleteProductFromRedis(ctx context.Context, productID string) error
}

type ProductsClientInterface interface {
	GetItemInfo(ctx context.Context, productIDs []string) ([]model.CartItem, error)
}

type CartService struct {
	cartRepo       CartRepoInterface
	productRepo    ProductsRepoInterface
	productsClient ProductsClientInterface
}

func New(cartRepo CartRepoInterface, productRepo ProductsRepoInterface,
	productsClient ProductsClientInterface) *CartService {

	return &CartService{cartRepo: cartRepo, productRepo: productRepo, productsClient: productsClient}
}

func (s *CartService) AddToCart(ctx context.Context, userID int, productID string, quantity int) error {

	// prometheus
	getTimer := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("cart", "GET"))
	defer getTimer.ObserveDuration()

	const op = "cart.service.AddToCart"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok {
		log = zap.NewNop()
	}

	// validation
	if userID <= 0 || productID == "" || quantity <= 0 {
		return errs.ErrInvalidRequest
	}

	cart, err := s.cartRepo.GetCartFromRedis(ctx, userID)
	if err != nil {

		log.Warn("❗failed to get cart from redis",
			zap.String(constants.LogComponentKey, op),
			zap.Error(err))

		// prometheus
		metrics.RedisErrorsTotal.WithLabelValues("cart", "GET").Inc() // prometheus
		getTimerDB := prometheus.NewTimer(metrics.PostgresOperationLatency.WithLabelValues("cart", "GET"))
		defer getTimerDB.ObserveDuration()

		// receive current cart of user
		cart, err = s.cartRepo.GetCartFromDB(ctx, userID)
		if err != nil {

			if errors.Is(err, errs.ErrNotFound) {
				log.Warn("👉 failed to get cart from DB",
					zap.String(constants.LogComponentKey, op),
					zap.Error(err))
				cart = &model.Cart{UserID: userID, Items: []model.CartItem{}} // create new cart

			} else {
				log.Error("❗failed to get cart from DB",
					zap.String(constants.LogComponentKey, op),
					zap.Error(err),
					zap.Int(constants.LogUserIDKey, userID),
				)

				metrics.PostgresErrorsTotal.WithLabelValues("cart", "GET").Inc() // prometheus
				return fmt.Errorf("failed to get cart: %w", err)
			}
		}
	}

	// add new item into cart (just in memory)
	log.Info("👉 adding items to cart in memory")
	cart.AddNewProductsIntoCart(productID, quantity)

	// prometheus
	setTimer := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("cart", "SET"))
	defer setTimer.ObserveDuration()

	// save to Redis
	err = s.cartRepo.SaveCartToRedis(ctx, cart)
	if err != nil {
		metrics.RedisErrorsTotal.WithLabelValues("cart", "SET").Inc() // prometheus

		log.Warn("❗failed to save cart to redis", zap.Error(err),
			zap.Int(constants.LogUserIDKey, userID),
		)
	}

	// create copy to avoid race condition
	cartCopy := model.Cart{
		UserID: cart.UserID,
		Items:  make([]model.CartItem, len(cart.Items)),
	}

	for i := range cart.Items {
		cartCopy.Items[i] = cart.Items[i]
	}

	// async save to DB
	go func(cart model.Cart, userID int, productID string, quantity int) {

		// prometheus
		setTimerDB := prometheus.NewTimer(metrics.PostgresOperationLatency.WithLabelValues("cart", "SET"))
		defer setTimerDB.ObserveDuration()

		err = s.cartRepo.SaveCartToDB(context.Background(), &cart)
		if err != nil {
			log.Error("❗failed to save cart to db",
				zap.Error(err),
				zap.Int(constants.LogUserIDKey, userID),
			)

			metrics.PostgresErrorsTotal.WithLabelValues("cart", "SET").Inc() // prometheus
			return
		}

		log.Info("✅ item added to cart successfully",
			zap.String(constants.LogComponentKey, op),
			zap.Int(constants.LogUserIDKey, userID),
			zap.String(constants.LogProductIDKey, productID),
			zap.Int("quantity", quantity),
		)
	}(cartCopy, userID, productID, quantity)

	return nil
}

func (s *CartService) RemoveFromCart(ctx context.Context, userID int, productID string) error {

	// prometheus
	getTimer := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("cart", "GET"))
	defer getTimer.ObserveDuration()

	const op = "cart.service.RemoveFromCart"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok {
		log = zap.NewNop()
	}

	// validation
	if userID <= 0 || productID == "" {
		return errs.ErrInvalidRequest
	}

	cart, err := s.cartRepo.GetCartFromRedis(ctx, userID)
	if err != nil {
		metrics.RedisErrorsTotal.WithLabelValues("cart", "GET").Inc() // prometheus

		// prometheus
		getTimerDB := prometheus.NewTimer(metrics.PostgresOperationLatency.WithLabelValues("cart", "GET"))
		defer getTimerDB.ObserveDuration()

		// receive current user's cart
		cart, err = s.cartRepo.GetCartFromDB(ctx, userID)
		if err != nil {

			if errors.Is(err, errs.ErrNotFound) {
				return errs.ErrNotFound
			}

			log.Error("failed to receive cart from DB",
				zap.String(constants.LogComponentKey, op),
				zap.Error(err),
				zap.Int(constants.LogUserIDKey, userID),
			)

			metrics.PostgresErrorsTotal.WithLabelValues("cart", "GET").Inc() // prometheus
			return fmt.Errorf("%s: failed to get cart: %w", op, err)

		} else if cart != nil {

			err = s.cartRepo.SaveCartToRedis(ctx, cart) // cache warm-up
			if err != nil {
				metrics.RedisErrorsTotal.WithLabelValues("cart", "SET").Inc() // prometheus
			}

		}
	}

	// remove item from cart (just in memory)
	if cart != nil {
		err = cart.RemoveItem(productID)
		if err != nil {
			return fmt.Errorf("failed to remove item from cart: %w", err)
		}
	}

	// prometheus
	setTimer := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("cart", "SET"))
	defer setTimer.ObserveDuration()

	// save to Redis
	err = s.cartRepo.SaveCartToRedis(ctx, cart)
	if err != nil {
		metrics.RedisErrorsTotal.WithLabelValues("cart", "SET").Inc() // prometheus

		log.Warn("failed to save cart to redis", zap.Error(err),
			zap.Int(constants.LogUserIDKey, userID),
		)
	}

	if cart == nil {
		return fmt.Errorf("%s: cart does not exist", op)
	}

	// create copy to avoid race condition
	cartCopy := model.Cart{
		UserID: cart.UserID,
		Items:  make([]model.CartItem, len(cart.Items)),
	}

	for i := range cart.Items {
		cartCopy.Items[i] = cart.Items[i]
	}

	// async save to DB
	go func(cart model.Cart, userID int, productID string) {

		// prometheus
		setTimerDB := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("cart", "SET"))
		defer setTimerDB.ObserveDuration()

		err = s.cartRepo.SaveCartToDB(context.Background(), &cart)
		if err != nil {
			metrics.PostgresErrorsTotal.WithLabelValues("cart", "SET").Inc() // prometheus

			log.Error("failed to save cart to db", zap.Error(err),
				zap.Int(constants.LogUserIDKey, userID),
			)
		} else {
			log.Info("item removed from cart successfully",
				zap.String(constants.LogComponentKey, op),
				zap.Int(constants.LogUserIDKey, userID),
				zap.String(constants.LogProductIDKey, productID),
			)
		}
	}(cartCopy, userID, productID)

	return nil
}

func (s *CartService) ClearCart(ctx context.Context, userID int) error {

	// prometheus
	timer := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("cart", "DEL"))
	defer timer.ObserveDuration()

	const op = "cart.service.ClearCart"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok {
		log = zap.NewNop()
	}

	// validation
	if userID <= 0 {
		return errs.ErrInvalidRequest
	}

	// delete from Redis
	err := s.cartRepo.ClearCartInRedis(ctx, userID)
	if err != nil {
		metrics.RedisErrorsTotal.WithLabelValues("cart", "DEL").Inc() // prometheus

		log.Warn("failed to remove cart from redis", zap.Error(err),
			zap.Int(constants.LogUserIDKey, userID),
		)
	}

	// async save to DB
	go func(userID int, log *zap.Logger) {

		// prometheus
		timerDB := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("cart", "DEL"))
		defer timerDB.ObserveDuration()

		err = s.cartRepo.ClearCartInDB(context.Background(), userID)
		metrics.PostgresErrorsTotal.WithLabelValues("cart", "DEL").Inc() // prometheus

		if err != nil {
			log.Error("failed to clear cart in db", zap.Error(err),
				zap.Int(constants.LogUserIDKey, userID),
				zap.String(constants.LogComponentKey, op),
			)
		} else {
			log.Info("cart cleared successfully in DB",
				zap.String(constants.LogComponentKey, op),
				zap.Int(constants.LogUserIDKey, userID),
			)
		}
	}(userID, log)

	return nil
}

func (s *CartService) GetCart(ctx context.Context, userID int) (*model.Cart, error) {

	const op = "cart.service.GetCart"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok {
		log = zap.NewNop()
	}

	// validation
	if userID <= 0 {
		return nil, errs.ErrInvalidRequest
	}

	// prometheus
	getTimer := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("cart", "GET"))
	defer getTimer.ObserveDuration()

	// try to receive current cart of user (just productID's and quantity)
	cart, err := s.cartRepo.GetCartFromRedis(ctx, userID)
	if err != nil {
		metrics.RedisErrorsTotal.WithLabelValues("cart", "GET").Inc() // prometheus

		// prometheus
		getTimerDB := prometheus.NewTimer(metrics.PostgresOperationLatency.WithLabelValues("cart", "GET"))
		defer getTimerDB.ObserveDuration()

		// receive current cart of user
		cart, err = s.cartRepo.GetCartFromDB(ctx, userID)
		if err != nil {

			if errors.Is(err, errs.ErrNotFound) {
				return nil, errs.ErrNotFound
			}

			log.Error("❌ failed to receive cart from DB",
				zap.String(constants.LogComponentKey, op),
				zap.Error(err),
				zap.Int(constants.LogUserIDKey, userID),
			)

			return nil, fmt.Errorf("%s: failed to get cart: %w", op, err)
		}

		// prometheus
		setTimer := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("cart", "SET"))
		defer setTimer.ObserveDuration()

		err = s.cartRepo.SaveCartToRedis(ctx, cart) // cache warm-up
		if err != nil {
			metrics.RedisErrorsTotal.WithLabelValues("cart", "SET").Inc() // prometheus

			log.Warn("failed to warm-up cart cache",
				zap.String(constants.LogComponentKey, op),
				zap.Error(err),
				zap.Int(constants.LogUserIDKey, userID),
			)
		}
	}

	cacheMissProducts := make([]string, 0)

	// search product info in cache
	for i, item := range cart.Items {
		// prometheus
		getTimerItem := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("item", "GET"))

		info, err := s.productRepo.GetProductFromRedis(ctx, item.ProductID)
		getTimerItem.ObserveDuration() // prometheus

		if err != nil {
			metrics.RedisErrorsTotal.WithLabelValues("item", "GET").Inc() // prometheus

			if errors.Is(err, errs.ErrNotFound) {
				cacheMissProducts = append(cacheMissProducts, item.ProductID) // cache miss
				continue
			} else if errors.Is(err, context.DeadlineExceeded) {

				log.Error("❗redis timeout, fallback to products service",
					zap.String(constants.LogComponentKey, op),
					zap.Error(err),
					zap.Int(constants.LogUserIDKey, userID),
				)
				cacheMissProducts = append(cacheMissProducts, item.ProductID) // cache miss
				continue
			} else {
				// if Redis unavailable → logging
				log.Error("❗redis unavailable, fallback to products service",
					zap.String(constants.LogComponentKey, op),
					zap.Error(err),
					zap.Int(constants.LogUserIDKey, userID),
				)
				cacheMissProducts = append(cacheMissProducts, item.ProductID)
				continue
			}
		}

		// save cache hit products info into cart
		if info != nil {
			cart.Items[i].Name = info.Name
			cart.Items[i].Price = info.Price
			cart.Items[i].Photo = info.Photo
		}
	}

	// if cacheMissProducts not empty → call RPC products.GetItemsInfo(cacheMissProducts)
	if len(cacheMissProducts) != 0 {
		products, err := s.productsClient.GetItemInfo(ctx, cacheMissProducts)
		if err != nil {
			return nil, fmt.Errorf("%s: ❌ failed to get products info by gRPC: %w", op, err)
		}

		// save cache miss products into cart
		productMap := make(map[string]model.CartItem, len(products))
		for _, p := range products {
			productMap[p.ProductID] = p
		}

		// check items returned from products-service, delete not found items
		finalItems := make([]model.CartItem, 0, len(cart.Items))

		for _, item := range cart.Items {
			p, ok := productMap[item.ProductID]
			if ok {
				item.Name = p.Name
				item.Price = p.Price
				item.Photo = p.Photo
				finalItems = append(finalItems, item)
			} else {
				// if item not found in products-service DB
				log.Warn("❗item missing in products-service, removing from cart",
					zap.String("product_id", item.ProductID),
					zap.String(constants.LogComponentKey, op),
				)
			}
		}

		cart.Items = finalItems

		// products cache warm-up
		for i := range products {
			// prometheus
			setTimerItem := prometheus.NewTimer(metrics.RedisOperationLatency.WithLabelValues("item", "SET"))

			err = s.productRepo.SaveProductToRedis(ctx, &(products)[i])
			setTimerItem.ObserveDuration() // prometheus

			if err != nil {
				metrics.RedisErrorsTotal.WithLabelValues("item", "SET").Inc() // prometheus

				log.Warn("❗failed to save product info to redis",
					zap.String(constants.LogComponentKey, op),
					zap.Error(err),
					zap.Int(constants.LogUserIDKey, userID),
				)
			}
		}

		// if products-service did not return all info of items
		if len(cacheMissProducts) != len(products) {

			// save to Redis
			err = s.cartRepo.SaveCartToRedis(ctx, cart)
			if err != nil {
				metrics.RedisErrorsTotal.WithLabelValues("cart", "SET").Inc() // prometheus

				log.Warn("❗failed to save cart to redis", zap.Error(err),
					zap.Int(constants.LogUserIDKey, userID),
				)
			}

			// create copy to avoid race condition
			cartCopy := model.Cart{
				UserID: cart.UserID,
				Items:  make([]model.CartItem, len(cart.Items)),
			}

			for i := range cart.Items {
				cartCopy.Items[i] = cart.Items[i]
			}

			// async save to DB
			go func(cart model.Cart, userID int) {

				// prometheus
				setTimerDB := prometheus.NewTimer(metrics.PostgresOperationLatency.WithLabelValues("cart", "SET"))
				defer setTimerDB.ObserveDuration()

				err := s.cartRepo.SaveCartToDB(context.Background(), &cart)
				if err != nil {
					log.Error("❗failed to save cart into db",
						zap.Error(err),
						zap.Int(constants.LogUserIDKey, userID),
					)

					metrics.PostgresErrorsTotal.WithLabelValues("cart", "SET").Inc() // prometheus
					return
				}

				log.Info("✅ items saved successfully",
					zap.String(constants.LogComponentKey, op),
					zap.Int(constants.LogUserIDKey, userID),
				)
			}(cartCopy, userID)
		}
	}

	cart.CalculateTotalPrice()

	return cart, nil
}
