package sam

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type API struct {
	Metadata            defsecTypes.MisconfigMetadata
	Name                defsecTypes.StringValue
	TracingEnabled      defsecTypes.BoolValue
	DomainConfiguration DomainConfiguration
	AccessLogging       AccessLogging
	RESTMethodSettings  RESTMethodSettings
}

type ApiAuth struct {
	Metadata       defsecTypes.MisconfigMetadata
	ApiKeyRequired defsecTypes.BoolValue
}

type AccessLogging struct {
	Metadata              defsecTypes.MisconfigMetadata
	CloudwatchLogGroupARN defsecTypes.StringValue
}

type DomainConfiguration struct {
	Metadata       defsecTypes.MisconfigMetadata
	Name           defsecTypes.StringValue
	SecurityPolicy defsecTypes.StringValue
}

type RESTMethodSettings struct {
	Metadata           defsecTypes.MisconfigMetadata
	CacheDataEncrypted defsecTypes.BoolValue
	LoggingEnabled     defsecTypes.BoolValue
	DataTraceEnabled   defsecTypes.BoolValue
	MetricsEnabled     defsecTypes.BoolValue
}
