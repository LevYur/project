package metrics

import "github.com/prometheus/client_golang/prometheus"

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
			ConstLabels: prometheus.Labels{"service": "gateway"}},
	)

	AuthRefreshFailedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "auth_refresh_failed_total",
			Help:        "Total failed refresh access_token",
			ConstLabels: prometheus.Labels{"service": "gateway"}},
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

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)

	prometheus.MustRegister(AuthRefreshSuccessTotal)
	prometheus.MustRegister(AuthRefreshFailedTotal)

	prometheus.MustRegister(GatewayInvalidLoginRequestTotal)
	prometheus.MustRegister(GatewayInvalidRegisterRequestTotal)
}
