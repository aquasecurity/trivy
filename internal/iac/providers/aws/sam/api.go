package sam

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type API struct {
	Metadata            iacTypes.Metadata
	Name                iacTypes.StringValue
	TracingEnabled      iacTypes.BoolValue
	DomainConfiguration DomainConfiguration
	AccessLogging       AccessLogging
	RESTMethodSettings  RESTMethodSettings
}

type ApiAuth struct {
	Metadata       iacTypes.Metadata
	ApiKeyRequired iacTypes.BoolValue
}

type AccessLogging struct {
	Metadata              iacTypes.Metadata
	CloudwatchLogGroupARN iacTypes.StringValue
}

type DomainConfiguration struct {
	Metadata       iacTypes.Metadata
	Name           iacTypes.StringValue
	SecurityPolicy iacTypes.StringValue
}

type RESTMethodSettings struct {
	Metadata           iacTypes.Metadata
	CacheDataEncrypted iacTypes.BoolValue
	LoggingEnabled     iacTypes.BoolValue
	DataTraceEnabled   iacTypes.BoolValue
	MetricsEnabled     iacTypes.BoolValue
}
