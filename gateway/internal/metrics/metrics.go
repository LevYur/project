package metrics

import "github.com/prometheus/client_golang/prometheus"

// auth-service (http)
var (
	HttpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "http_requests_total",
			Help:        "Total HTTP requests",
			ConstLabels: prometheus.Labels{"service": "gateway"},
		},
		[]string{"method", "path", "status"},
	)

	HttpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	AuthRefreshSuccessTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "auth_refresh_success_total",
			Help:        "Total success refresh access_token",
			ConstLabels: prometheus.Labels{"service": "gateway", "server": "auth"}},
	)

	AuthRefreshFailedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "auth_refresh_failed_total",
			Help:        "Total failed refresh access_token",
			ConstLabels: prometheus.Labels{"service": "gateway", "server": "auth"}},
		[]string{"reason"})

	GatewayInvalidLoginRequestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "gateway_invalid_login_request_total",
			Help:        "Total invalid login requests",
			ConstLabels: prometheus.Labels{"service": "gateway"}},
		[]string{"reason"})

	GatewayInvalidRegisterRequestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "gateway_invalid_register_request_total",
			Help:        "Total invalid register requests",
			ConstLabels: prometheus.Labels{"service": "gateway"}},
		[]string{"reason"})
)

// cart-service (grpc) metrics
var (
	GPRCRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "grpc_requests_total",
			Help:        "Total gRPC requests",
			ConstLabels: prometheus.Labels{"service": "gateway"},
		},
		[]string{"server", "method", "status"},
	)

	GRPCRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "grpc_request_duration_seconds",
			Help:    "grpc request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"server", "method"},
	)
)

func init() {

	// auth-service (http)
	prometheus.MustRegister(HttpRequestsTotal)
	prometheus.MustRegister(HttpRequestDuration)

	prometheus.MustRegister(AuthRefreshSuccessTotal)
	prometheus.MustRegister(AuthRefreshFailedTotal)

	prometheus.MustRegister(GatewayInvalidLoginRequestTotal)
	prometheus.MustRegister(GatewayInvalidRegisterRequestTotal)

	// cart-service (grpc)
	prometheus.MustRegister(GPRCRequestsTotal)
	prometheus.MustRegister(GRPCRequestDuration)
}
