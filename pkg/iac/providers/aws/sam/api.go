package sam

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type API struct {
	Metadata            defsecTypes.Metadata
	Name                defsecTypes.StringValue
	TracingEnabled      defsecTypes.BoolValue
	DomainConfiguration DomainConfiguration
	AccessLogging       AccessLogging
	RESTMethodSettings  RESTMethodSettings
}

type ApiAuth struct {
	Metadata       defsecTypes.Metadata
	ApiKeyRequired defsecTypes.BoolValue
}

type AccessLogging struct {
	Metadata              defsecTypes.Metadata
	CloudwatchLogGroupARN defsecTypes.StringValue
}

type DomainConfiguration struct {
	Metadata       defsecTypes.Metadata
	Name           defsecTypes.StringValue
	SecurityPolicy defsecTypes.StringValue
}

type RESTMethodSettings struct {
	Metadata           defsecTypes.Metadata
	CacheDataEncrypted defsecTypes.BoolValue
	LoggingEnabled     defsecTypes.BoolValue
	DataTraceEnabled   defsecTypes.BoolValue
	MetricsEnabled     defsecTypes.BoolValue
}
