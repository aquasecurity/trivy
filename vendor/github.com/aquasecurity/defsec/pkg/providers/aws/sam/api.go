package sam

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type API struct {
	types.Metadata
	Name                types.StringValue
	TracingEnabled      types.BoolValue
	DomainConfiguration DomainConfiguration
	AccessLogging       AccessLogging
	RESTMethodSettings  RESTMethodSettings
}

type ApiAuth struct {
	types.Metadata
	ApiKeyRequired types.BoolValue
}

type AccessLogging struct {
	types.Metadata
	CloudwatchLogGroupARN types.StringValue
}

type DomainConfiguration struct {
	types.Metadata
	Name           types.StringValue
	SecurityPolicy types.StringValue
}

type RESTMethodSettings struct {
	types.Metadata
	CacheDataEncrypted types.BoolValue
	LoggingEnabled     types.BoolValue
	DataTraceEnabled   types.BoolValue
	MetricsEnabled     types.BoolValue
}
