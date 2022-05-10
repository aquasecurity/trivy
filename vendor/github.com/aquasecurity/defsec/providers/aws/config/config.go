package config

import "github.com/aquasecurity/defsec/parsers/types"

type Config struct {
	types.Metadata
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	types.Metadata
	SourceAllRegions types.BoolValue
	IsDefined        bool
}
