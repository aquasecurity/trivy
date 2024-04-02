package sam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sam"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getApis(cfFile parser.FileContext) (apis []sam.API) {

	apiResources := cfFile.GetResourcesByType("AWS::Serverless::Api")
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

func getRestMethodSettings(r *parser.Resource) []sam.RESTMethodSettings {

	var settings []sam.RESTMethodSettings

	methodSettings := r.GetProperty("MethodSettings")
	if methodSettings.IsNotList() {
		return nil
	}

	for _, el := range methodSettings.AsList() {

		methodSetting := sam.RESTMethodSettings{
			Metadata:           el.Metadata(),
			CacheDataEncrypted: el.GetBoolProperty("CacheDataEncrypted"),
			DataTraceEnabled:   el.GetBoolProperty("DataTraceEnabled"),
			MetricsEnabled:     el.GetBoolProperty("MetricsEnabled"),
		}

		if loggingLevel := methodSettings.GetProperty("LoggingLevel"); loggingLevel.IsNotNil() {
			methodSetting.LoggingEnabled = iacTypes.Bool(!loggingLevel.EqualTo("OFF"), loggingLevel.Metadata())
		}

		settings = append(settings, methodSetting)
	}

	return settings
}

func getAccessLogging(r *parser.Resource) sam.AccessLogging {

	logging := sam.AccessLogging{
		Metadata:              r.Metadata(),
		CloudwatchLogGroupARN: iacTypes.StringDefault("", r.Metadata()),
	}

	if access := r.GetProperty("AccessLogSetting"); access.IsNotNil() {
		logging = sam.AccessLogging{
			Metadata:              access.Metadata(),
			CloudwatchLogGroupARN: access.GetStringProperty("DestinationArn", ""),
		}
	}

	return logging
}

func getDomainConfiguration(r *parser.Resource) sam.DomainConfiguration {

	domainConfig := sam.DomainConfiguration{
		Metadata: r.Metadata(),
	}

	if domain := r.GetProperty("Domain"); domain.IsNotNil() {
		domainConfig = sam.DomainConfiguration{
			Metadata:       domain.Metadata(),
			Name:           domain.GetStringProperty("DomainName"),
			SecurityPolicy: domain.GetStringProperty("SecurityPolicy"),
		}
	}

	return domainConfig

}
