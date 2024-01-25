package sam

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type HttpAPI struct {
	Metadata             defsecTypes.MisconfigMetadata
	Name                 defsecTypes.StringValue
	AccessLogging        AccessLogging
	DefaultRouteSettings RouteSettings
	DomainConfiguration  DomainConfiguration
}

type RouteSettings struct {
	Metadata               defsecTypes.MisconfigMetadata
	LoggingEnabled         defsecTypes.BoolValue
	DataTraceEnabled       defsecTypes.BoolValue
	DetailedMetricsEnabled defsecTypes.BoolValue
}
