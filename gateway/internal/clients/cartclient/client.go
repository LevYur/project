// создание gRPC клиента
// хранение pb.CartServiceClient
// методы AddItem/GetCart/DeleteItem

package cartclient

import (
	"context"
	"gateway/pkg/constants"
	cartextv1 "github.com/LevYur/project-protos/cart/external/gen.v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"time"
)

type CartClient struct {
	client cartextv1.CartServiceClient
	conn   *grpc.ClientConn
	log    *zap.Logger
}

func New(log *zap.Logger, opts ...Option) *CartClient {

	start := time.Now()

	const op = "gateway.internal.client.cart"

	cfg := defaultConfig()

	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.endpoint == "" {
		log.Fatal("failed to gRPC connect to cart-service: empty address",
			zap.String(constants.LogComponentKey, op))
		return nil
	}

	if cfg.serviceConfig != "" {
		cfg.dialOptions = append(cfg.dialOptions,
			grpc.WithDefaultServiceConfig(cfg.serviceConfig))
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.dialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.endpoint, cfg.dialOptions...)
	if err != nil {
		log.Fatal("failed to gRPC connect to cart-service", zap.Error(err))
		return nil
	} else {
		log.Info("👉 cart grpc dial OK")
	}

	log.Info("Dial completed", zap.Duration("duration", time.Since(start)))

	client := cartextv1.NewCartServiceClient(conn)

	return &CartClient{client: client, conn: conn, log: log}
}

func (c *CartClient) Close() error {
	return c.conn.Close()
}

func (c *CartClient) AddToCart(
	ctx context.Context, req *cartextv1.AddToCartRequest) (*cartextv1.CartBoolResponse, error) {

	const op = "gateway.client.cart.AddToCart"

	c.log.Debug("remote calling AddToCart",
		zap.String(constants.LogComponentKey, op),
		zap.Int64(constants.LogUserIDKey, req.UserId),
		zap.String(constants.LogProductIDKey, req.ProductId),
		zap.Int32(constants.LogQuantityKey, req.Quantity),
	)

	resp, err := c.client.AddToCart(ctx, req)
	if err != nil {
		c.log.Error("calling AddToCart failed", zap.Error(err))
		return nil, err
	}

	return resp, nil
}

func (c *CartClient) RemoveFromCart(
	ctx context.Context, req *cartextv1.RemoveFromCartRequest) (*cartextv1.CartBoolResponse, error) {

	const op = "gateway.client.cart.RemoveFromCart"

	c.log.Debug("remote calling RemoveFromCart",
		zap.String(constants.LogComponentKey, op),
		zap.Int64(constants.LogUserIDKey, req.UserId),
		zap.String(constants.LogProductIDKey, req.ProductId),
	)

	resp, err := c.client.RemoveFromCart(ctx, req)
	if err != nil {
		c.log.Error("calling RemoveFromCart failed", zap.Error(err))
		return nil, err
	}

	return resp, nil
}

func (c *CartClient) ClearCart(
	ctx context.Context, req *cartextv1.ClearCartRequest) (*cartextv1.CartBoolResponse, error) {

	const op = "gateway.client.cart.ClearCart"

	c.log.Debug("remote calling ClearCart",
		zap.String(constants.LogComponentKey, op),
		zap.Int64(constants.LogUserIDKey, req.UserId),
	)

	resp, err := c.client.ClearCart(ctx, req)
	if err != nil {
		c.log.Error("calling ClearCart failed", zap.Error(err))
		return nil, err
	}

	return resp, nil
}

func (c *CartClient) GetCart(
	ctx context.Context, req *cartextv1.GetCartRequest) (*cartextv1.GetCartResponse, error) {

	const op = "gateway.client.cart.GetCart"

	c.log.Debug("remote calling GetCart",
		zap.String(constants.LogComponentKey, op),
		zap.Int64(constants.LogUserIDKey, req.UserId),
	)

	resp, err := c.client.GetCart(ctx, req)
	if err != nil {
		c.log.Error("calling GetCart failed", zap.Error(err))
		return nil, err
	}

	return resp, nil
}
