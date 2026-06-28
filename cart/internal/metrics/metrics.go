package metrics

import "github.com/prometheus/client_golang/prometheus"

// handler metrics
var (
	CartAddTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "cart_add_total",
		Help:        "Total add item to cart requests",
		ConstLabels: prometheus.Labels{"service": "cart", "source": "gateway", "component": "handler"},
	},
		[]string{"rpc_method", "status"},
	)

	CartRemoveTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "cart_remove_total",
		Help:        "Total remove item from cart requests",
		ConstLabels: prometheus.Labels{"service": "cart", "source": "gateway", "component": "handler"},
	},
		[]string{"rpc_method", "status"},
	)

	CartClearTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "cart_clear_total",
		Help:        "Total clear cart requests",
		ConstLabels: prometheus.Labels{"service": "cart", "source": "gateway", "component": "handler"},
	},
		[]string{"rpc_method", "status"},
	)

	CartGetTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "cart_get_total",
		Help:        "Total get cart requests",
		ConstLabels: prometheus.Labels{"service": "cart", "source": "gateway", "component": "handler"},
	},
		[]string{"rpc_method", "status"},
	)

	HandlerDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "cart_handler_duration_seconds",
		Help:    "Handler request duration in seconds",
		Buckets: prometheus.DefBuckets,
	},
		[]string{"rpc_method"},
	)
)

// service metrics
var (
	RedisErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "redis_errors_total",
		Help:        "Total number of Redis errors",
		ConstLabels: prometheus.Labels{"service": "cart", "component": "service"},
	},
		[]string{"want", "operation"},
	)

	RedisOperationLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "redis_operation_latency_seconds",
		Help:    "Latency of Redis operations",
		Buckets: prometheus.DefBuckets,
	},
		[]string{"want", "operation"},
	)

	PostgresErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "db_errors_total",
		Help:        "Total number of DB errors",
		ConstLabels: prometheus.Labels{"service": "cart", "component": "service"},
	},
		[]string{"want", "operation"},
	)

	PostgresOperationLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "db_operation_latency_seconds",
		Help:    "Latency of DB operations",
		Buckets: prometheus.DefBuckets,
	},
		[]string{"want", "operation"},
	)
)

// repository metrics
var (
	PostgresQueryTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "db_query_total",
		Help:        "Total number of DB queries",
		ConstLabels: prometheus.Labels{"service": "cart", "component": "service"},
	},
		[]string{"query"},
	)

	PostgresQueryLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "db_query_latency_seconds",
		Help:    "Latency of DB queries",
		Buckets: prometheus.DefBuckets,
	},
		[]string{"query"},
	)
)

func init() {

	// handler metrics
	prometheus.MustRegister(CartAddTotal)
	prometheus.MustRegister(CartRemoveTotal)
	prometheus.MustRegister(CartClearTotal)
	prometheus.MustRegister(CartGetTotal)
	prometheus.MustRegister(HandlerDuration)

	// service metrics
	prometheus.MustRegister(RedisErrorsTotal)
	prometheus.MustRegister(RedisOperationLatency)
	prometheus.MustRegister(PostgresErrorsTotal)
	prometheus.MustRegister(PostgresOperationLatency)

	// repo metrics
	prometheus.MustRegister(PostgresQueryTotal)
	prometheus.MustRegister(PostgresQueryLatency)
}
