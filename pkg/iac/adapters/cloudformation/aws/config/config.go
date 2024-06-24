package config

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/config"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a configurationaggregator instance
func Adapt(cfFile parser.FileContext) config.Config {
	return config.Config{
		ConfigurationAggregrator: getConfigurationAggregator(cfFile),
	}
}
