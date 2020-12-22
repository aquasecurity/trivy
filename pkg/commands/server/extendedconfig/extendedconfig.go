package extendedconfig

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/trivy/pkg/commands/server/config"
)

// ExtendedConfig represents prometheus-related configuration alongside the provided config.Config
type ExtendedConfig struct {
	Config          config.Config
	MetricsRegistry *prometheus.Registry
	GaugeMetric     *prometheus.GaugeVec
}

// New bootstraps an ExtendedConfig object out of a config.Config object for further operation
func New(c config.Config) ExtendedConfig {
	return ExtendedConfig{
		Config: c,
	}
}

// Init populates the relevant prometheus-related configuration in an ExtendedConfig object
func (ec *ExtendedConfig) Init() {
	ec.MetricsRegistry = prometheus.NewRegistry()
	ec.GaugeMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trivy",
			Help: "Gauge Metrics associated with trivy - Last DB Update, Last DB Update Attempt ...",
		},
		[]string{"action"},
	)
	ec.MetricsRegistry.MustRegister(ec.GaugeMetric)
}
