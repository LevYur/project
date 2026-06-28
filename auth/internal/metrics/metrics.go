package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	AuthLoginSuccessTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "auth_logins_success_total",
			Help:        "Total success logins",
			ConstLabels: prometheus.Labels{"service": "auth"}},
	)

	AuthLoginFailedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "auth_logins_failed_total",
			Help:        "Total failed logins",
			ConstLabels: prometheus.Labels{"service": "auth"}},
		[]string{"reason"})

	AuthRegisterSuccessTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "auth_registers_success_total",
			Help:        "Total success registers",
			ConstLabels: prometheus.Labels{"service": "auth"}},
	)

	AuthRegisterFailedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "auth_registers_failed_total",
			Help:        "Total failed registers",
			ConstLabels: prometheus.Labels{"service": "auth"}},
		[]string{"reason"})

	AuthRefreshSuccessTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name:        "auth_refresh_success_total",
			Help:        "Total success refresh",
			ConstLabels: prometheus.Labels{"service": "auth"}},
	)

	AuthRefreshFailedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "auth_refresh_failed_total",
			Help:        "Total failed refresh",
			ConstLabels: prometheus.Labels{"service": "auth"}},
		[]string{"reason"})
)

func init() {
	prometheus.MustRegister(AuthLoginSuccessTotal)
	prometheus.MustRegister(AuthLoginFailedTotal)

	prometheus.MustRegister(AuthRegisterSuccessTotal)
	prometheus.MustRegister(AuthRegisterFailedTotal)

	prometheus.MustRegister(AuthRefreshSuccessTotal)
	prometheus.MustRegister(AuthRefreshFailedTotal)
}
