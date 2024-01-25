package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
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

func getRestMethodSettings(r *parser.Resource) sam.RESTMethodSettings {

	settings := sam.RESTMethodSettings{
		Metadata:           r.Metadata(),
		CacheDataEncrypted: defsecTypes.BoolDefault(false, r.Metadata()),
		LoggingEnabled:     defsecTypes.BoolDefault(false, r.Metadata()),
		DataTraceEnabled:   defsecTypes.BoolDefault(false, r.Metadata()),
		MetricsEnabled:     defsecTypes.BoolDefault(false, r.Metadata()),
	}

	settingsProp := r.GetProperty("MethodSettings")
	if settingsProp.IsNotNil() {

		settings = sam.RESTMethodSettings{
			Metadata:           settingsProp.Metadata(),
			CacheDataEncrypted: settingsProp.GetBoolProperty("CacheDataEncrypted"),
			LoggingEnabled:     defsecTypes.BoolDefault(false, settingsProp.Metadata()),
			DataTraceEnabled:   settingsProp.GetBoolProperty("DataTraceEnabled"),
			MetricsEnabled:     settingsProp.GetBoolProperty("MetricsEnabled"),
		}

		if loggingLevel := settingsProp.GetProperty("LoggingLevel"); loggingLevel.IsNotNil() {
			if loggingLevel.EqualTo("OFF", parser.IgnoreCase) {
				settings.LoggingEnabled = defsecTypes.Bool(false, loggingLevel.Metadata())
			} else {
				settings.LoggingEnabled = defsecTypes.Bool(true, loggingLevel.Metadata())
			}
		}
	}

	return settings
}

func getAccessLogging(r *parser.Resource) sam.AccessLogging {

	logging := sam.AccessLogging{
		Metadata:              r.Metadata(),
		CloudwatchLogGroupARN: defsecTypes.StringDefault("", r.Metadata()),
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
		Metadata:       r.Metadata(),
		Name:           defsecTypes.StringDefault("", r.Metadata()),
		SecurityPolicy: defsecTypes.StringDefault("TLS_1_0", r.Metadata()),
	}

	if domain := r.GetProperty("Domain"); domain.IsNotNil() {
		domainConfig = sam.DomainConfiguration{
			Metadata:       domain.Metadata(),
			Name:           domain.GetStringProperty("DomainName", ""),
			SecurityPolicy: domain.GetStringProperty("SecurityPolicy", "TLS_1_0"),
		}
	}

	return domainConfig

}
