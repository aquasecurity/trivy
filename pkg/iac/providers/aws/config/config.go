package config

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	Metadata         defsecTypes.Metadata
	SourceAllRegions defsecTypes.BoolValue
}
