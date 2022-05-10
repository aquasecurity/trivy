package sam

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/sam"
)

func getApis(cfFile parser.FileContext) (apis []sam.API) {

	apiResources := cfFile.GetResourceByType("AWS::Serverless::Api")
	for _, r := range apiResources {
		api := sam.API{
			Metadata:            r.Metadata(),
			Name:                r.GetStringProperty("Name", ""),
			TracingEnabled:      r.GetBoolProperty("TracingEnabled"),
			DomainConfiguration: getDomainConfiguration(r),
			AccessLogging:       getAccessLogging(r),
			RESTMethodSettings:  getRestMethodSettings(r),
		}

		apis = append(apis, api)
	}

	return apis
}

func getRestMethodSettings(r *parser.Resource) (methodSettings sam.RESTMethodSettings) {

	settings := r.GetProperty("MethodSettings")
	if settings.IsNil() {
		return sam.RESTMethodSettings{
			Metadata:           r.Metadata(),
			CacheDataEncrypted: types.BoolDefault(false, r.Metadata()),
			LoggingEnabled:     types.BoolDefault(false, r.Metadata()),
			DataTraceEnabled:   types.BoolDefault(false, r.Metadata()),
			MetricsEnabled:     types.BoolDefault(false, r.Metadata()),
		}
	}

	loggingEnabled := types.BoolDefault(false, settings.Metadata())
	if settings.GetProperty("LoggingLevel").IsNotNil() {
		loggingLevel := settings.GetProperty("LoggingLevel")
		if settings.GetProperty("LoggingLevel").EqualTo("OFF", parser.IgnoreCase) {
			loggingEnabled = types.BoolExplicit(false, loggingLevel.Metadata())
		} else {
			loggingEnabled = types.BoolExplicit(true, loggingLevel.Metadata())
		}

	}

	return sam.RESTMethodSettings{
		Metadata:           settings.Metadata(),
		CacheDataEncrypted: settings.GetBoolProperty("CacheDataEncrypted"),
		LoggingEnabled:     loggingEnabled,
		DataTraceEnabled:   settings.GetBoolProperty("DataTraceEnabled"),
		MetricsEnabled:     settings.GetBoolProperty("MetricsEnabled"),
	}

}

func getAccessLogging(r *parser.Resource) (accessLogging sam.AccessLogging) {

	access := r.GetProperty("AccessLogSetting")
	if access.IsNil() {
		return sam.AccessLogging{
			Metadata:              r.Metadata(),
			CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
		}
	}

	return sam.AccessLogging{
		Metadata:              access.Metadata(),
		CloudwatchLogGroupARN: access.GetStringProperty("DestinationArn", ""),
	}
}

func getDomainConfiguration(r *parser.Resource) (domainConfig sam.DomainConfiguration) {

	domain := r.GetProperty("Domain")
	if domain.IsNil() {
		domainConfig.SecurityPolicy = types.StringDefault("TLS_1_0", r.Metadata())
		return domainConfig
	}

	return sam.DomainConfiguration{
		Metadata:       domain.Metadata(),
		Name:           domain.GetStringProperty("DomainName", ""),
		SecurityPolicy: domain.GetStringProperty("SecurityPolicy", "TLS_1_0"),
	}

}
