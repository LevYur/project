package productsclient

import (
	"cartmodule/internal/config"
	"cartmodule/internal/constants"
	"cartmodule/internal/model"
	"context"
	"fmt"
	prodextv1 "github.com/LevYur/project-protos/products/external/gen/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"time"
)

type ProductsClient struct {
	conn   *grpc.ClientConn
	client prodextv1.ProductsServiceClient
	log    *zap.Logger
}

func New(cfg *config.Config, log *zap.Logger) *ProductsClient {

	optsSC := grpc.WithDefaultServiceConfig(`{
  "loadBalancingConfig": [{"round_robin":{}}],
  "methodConfig": [{
    "name": [{"service":"prodextv1.ProductsService"}],
    "retryPolicy": {
      "maxAttempts": 5,
      "initialBackoff": "0.2s",
      "maxBackoff": "3s",
      "backoffMultiplier": 2,
      "retryableStatusCodes": ["UNAVAILABLE", "DEADLINE_EXCEEDED"]
    }
  }]
}`)

	var conn *grpc.ClientConn
	var err error

	for {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.GRPCClient.DialTimeout)

		conn, err = grpc.DialContext(
			ctx,
			cfg.ProductsServiceGRPCAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
			optsSC,
			grpc.WithDisableServiceConfig(),
		)
		cancel()

		if err == nil {
			log.Info("✅ connected witt products-service by gRPC")
			break
		}

		log.Warn("👉 failed to connect to products-service, retrying...",
			zap.Error(err))

		time.Sleep(cfg.GRPCClient.RetryBackoff)
	}

	client := prodextv1.NewProductsServiceClient(conn)

	return &ProductsClient{conn: conn, client: client, log: log}
}

func (c *ProductsClient) GetItemInfo(
	ctx context.Context, productIDs []string) ([]model.CartItem, error) {

	const op = "cart.client.productsClient(grpc)"

	log, ok := ctx.Value(constants.LoggerCtxKey).(*zap.Logger)
	if !ok {
		log = c.log
	}

	req := &prodextv1.CartInfoRequest{Ids: productIDs}

	resp, err := c.client.InfoForCart(ctx, req)
	if err != nil {
		st, _ := status.FromError(err)

		log.Error("❌ failed to get items info from products-service by gRPC",
			zap.String(constants.LogStatusKey, st.Code().String()),
			zap.String(constants.LogMessageIDKey, st.Message()),
			zap.String(constants.LogComponentKey, op),
			zap.Error(err))

		return nil, err
	}

	// logging missing items
	missingItems := ""
	foundItemsMap := make(map[string]struct{})
	for _, item := range resp.Items {
		foundItemsMap[item.ProductId] = struct{}{}
	}

	for _, id := range productIDs {
		_, ok = foundItemsMap[id]
		if !ok {
			missingItems += fmt.Sprintf("%s, ", id)
		}
	}
	if missingItems != "" {
		log.Warn("❗some products are missing in products-service by gRPC:",
			zap.String("missing_items_id", missingItems),
			zap.String(constants.LogComponentKey, op),
		)
	}

	items := make([]model.CartItem, len(resp.Items))
	for i, item := range resp.Items {
		items[i] = model.CartItem{
			ProductID: item.ProductId,
			Name:      item.Name,
			Price:     item.Price,
			Photo:     item.Photo,
		}
	}

	return items, nil
}
