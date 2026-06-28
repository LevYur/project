package metrics

import (
	"cartmodule/internal/constants"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"net/http"
)

func StartMetricsServer(addr string, log *zap.Logger) {

	const op = "cart.internal.StartMetricsServer"

	http.Handle("/api/cart/metrics", promhttp.Handler())

	log.Info("starting cart-service prometheus metrics on " + addr)

	go func() {
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			log.Fatal("❌ failed cart-service prometheus metrics run",
				zap.String(constants.LogComponentKey, op), zap.Error(err),
			)
		}
	}()
}
