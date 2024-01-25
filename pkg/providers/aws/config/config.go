package config

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	Metadata         defsecTypes.MisconfigMetadata
	SourceAllRegions defsecTypes.BoolValue
}
