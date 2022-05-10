package sam

import "github.com/aquasecurity/defsec/parsers/types"

type HttpAPI struct {
	types.Metadata
	Name                 types.StringValue
	AccessLogging        AccessLogging
	DefaultRouteSettings RouteSettings
	DomainConfiguration  DomainConfiguration
}

type RouteSettings struct {
	types.Metadata
	LoggingEnabled         types.BoolValue
	DataTraceEnabled       types.BoolValue
	DetailedMetricsEnabled types.BoolValue
}
