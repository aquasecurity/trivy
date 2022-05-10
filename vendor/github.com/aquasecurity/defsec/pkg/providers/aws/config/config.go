package config

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	types.Metadata
	SourceAllRegions types.BoolValue
	IsDefined        bool
}
