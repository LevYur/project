package repository

import (
	"cartmodule/internal/errs"
	"cartmodule/internal/metrics"
	"cartmodule/internal/model"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"time"
)

type CartRepo struct {
	DB       *sql.DB
	RDB      *redis.Client
	RedisTTL time.Duration
}

type ProductRepo struct {
	RDB      *redis.Client
	RedisTTL time.Duration
}

func NewCartRepo(db *sql.DB, redisClient *redis.Client, ttl time.Duration) *CartRepo {

	return &CartRepo{
		DB:       db,
		RDB:      redisClient,
		RedisTTL: ttl}
}

func NewProductRepo(redisClient *redis.Client, ttl time.Duration) *ProductRepo {

	return &ProductRepo{
		RDB:      redisClient,
		RedisTTL: ttl}
}

// Cart methods

func (r *CartRepo) GetCartFromRedis(ctx context.Context, userID int) (*model.Cart, error) {

	const op = "cart.repo.GetFromRedis"

	key := fmt.Sprintf("cart:%d", userID)

	cartBytes, err := r.RDB.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errs.ErrNotFound
		}

		return nil, fmt.Errorf("%s: redis GET failed, %w", op, err)
	}

	var cart model.Cart
	err = json.Unmarshal(cartBytes, &cart)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal cart, %w", err)
	}

	return &cart, nil
}

func (r *CartRepo) GetCartFromDB(ctx context.Context, userID int) (*model.Cart, error) {

	// prometheus
	timer := prometheus.NewTimer(metrics.PostgresQueryLatency.WithLabelValues("GET"))
	defer timer.ObserveDuration()

	const op = "cart.repo.GetFromDB"

	query := `SELECT items FROM carts WHERE user_id=$1;`

	var itemsJSON []byte

	err := r.DB.QueryRowContext(ctx, query, userID).Scan(&itemsJSON)
	metrics.PostgresQueryTotal.WithLabelValues("GET").Inc() // prometheus

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, fmt.Errorf("%s: postgres get cart failed, %w", op, err)
	}

	var items []model.CartItem
	err = json.Unmarshal(itemsJSON, &items)
	if err != nil {
		return nil, fmt.Errorf("%s: unmarshal cart failed, %w", op, err)
	}

	cart := &model.Cart{
		UserID: userID,
		Items:  items, // just product_id and quantity
	}

	return cart, nil
}

func (r *CartRepo) SaveCartToRedis(ctx context.Context, cart *model.Cart) error {

	const op = "cart.repo.SaveToRedis"

	key := fmt.Sprintf("cart:%d", cart.UserID)

	cartBytes, err := json.Marshal(cart)
	if err != nil {
		return fmt.Errorf("%s: json marshal failed: %w", op, err)
	}

	err = r.RDB.Set(ctx, key, cartBytes, r.RedisTTL).Err()
	if err != nil {
		return fmt.Errorf("%s: redis SET failed, %w", op, err)
	}

	return nil
}

func (r *CartRepo) SaveCartToDB(ctx context.Context, cart *model.Cart) error {

	// prometheus
	timer := prometheus.NewTimer(metrics.PostgresQueryLatency.WithLabelValues("SET"))
	defer timer.ObserveDuration()

	const op = "cart.repo.SaveToDB"

	itemsJSON, err := json.Marshal(cart.Items)
	if err != nil {
		return fmt.Errorf("%s: marshal items failed: %w", op, err)
	}

	query := `
		INSERT INTO carts (user_id, items) 
		VALUES ($1, $2) 
		ON CONFLICT (user_id) DO UPDATE 
		SET items = EXCLUDED.items,
		updated_at = NOW();
	`

	_, err = r.DB.ExecContext(ctx, query, cart.UserID, itemsJSON)
	metrics.PostgresQueryTotal.WithLabelValues("SET").Inc() // prometheus

	if err != nil {
		return fmt.Errorf("%s: postgres save cart failed, %w", op, err)
	}

	return nil
}

func (r *CartRepo) ClearCartInRedis(ctx context.Context, userID int) error {

	const op = "cart.repo.ClearInRedis"

	key := fmt.Sprintf("cart:%d", userID)

	err := r.RDB.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("%s: redis DELETE failed, %w", op, err)
	}

	return nil
}

func (r *CartRepo) ClearCartInDB(ctx context.Context, userID int) error {

	// prometheus
	timer := prometheus.NewTimer(metrics.PostgresQueryLatency.WithLabelValues("DEL"))
	defer timer.ObserveDuration()

	const op = "cart.repo.ClearInDB"

	query := `
		DELETE FROM carts 
		WHERE user_id = $1;
	`

	_, err := r.DB.ExecContext(ctx, query, userID)
	metrics.PostgresQueryTotal.WithLabelValues("DEL").Inc() // prometheus

	if err != nil {
		return fmt.Errorf("%s: postgres delete cart failed, %w", op, err)
	}

	return nil
}

// Products methods

func (r *ProductRepo) GetProductFromRedis(
	ctx context.Context, productID string) (*model.CartItem, error) {

	const op = "cart.repo.GetProductFromRedis"

	key := fmt.Sprintf("product:%s", productID)

	dataBytes, err := r.RDB.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errs.ErrNotFound
		}

		return nil, fmt.Errorf("%s: redis GET failed, %w", op, err)
	}

	var product model.CartItem
	err = json.Unmarshal(dataBytes, &product)
	if err != nil {
		return nil, fmt.Errorf("%s: unmarshal error: %w", op, err)
	}

	return &product, nil
}

func (r *ProductRepo) SaveProductToRedis(ctx context.Context, product *model.CartItem) error {

	const op = "cart.repo.SaveProductToRedis"

	key := fmt.Sprintf("product:%s", product.ProductID)

	productBytes, err := json.Marshal(product)
	if err != nil {
		return fmt.Errorf("%s: json marshal failed: %w", op, err)
	}

	err = r.RDB.Set(ctx, key, productBytes, r.RedisTTL).Err()
	if err != nil {
		return fmt.Errorf("%s: redis SET failed, %w", op, err)
	}

	return nil
}

func (r *ProductRepo) DeleteProductFromRedis(ctx context.Context, productID string) error {

	const op = "cart.repo.DeleteProductFromRedis"

	key := fmt.Sprintf("product:%s", productID)

	err := r.RDB.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("%s: redis DELETE failed, %w", op, err)
	}

	return nil
}
