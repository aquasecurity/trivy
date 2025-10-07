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

func getRestMethodSettings(r *parser.Resource) sam.RESTMethodSettings {

	settings := sam.RESTMethodSettings{
		Metadata:           r.Metadata(),
		CacheDataEncrypted: iacTypes.BoolDefault(false, r.Metadata()),
		LoggingEnabled:     iacTypes.BoolDefault(false, r.Metadata()),
		DataTraceEnabled:   iacTypes.BoolDefault(false, r.Metadata()),
		MetricsEnabled:     iacTypes.BoolDefault(false, r.Metadata()),
	}

	// TODO: MethodSettings is list
	// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html#cfn-apigateway-stage-methodsettings
	settingsProp := r.GetProperty("MethodSettings")
	if settingsProp.IsNotNil() {

		settings = sam.RESTMethodSettings{
			Metadata:           settingsProp.Metadata(),
			CacheDataEncrypted: settingsProp.GetBoolProperty("CacheDataEncrypted"),
			LoggingEnabled:     iacTypes.BoolDefault(false, settingsProp.Metadata()),
			DataTraceEnabled:   settingsProp.GetBoolProperty("DataTraceEnabled"),
			MetricsEnabled:     settingsProp.GetBoolProperty("MetricsEnabled"),
		}

		if loggingLevel := settingsProp.GetProperty("LoggingLevel"); loggingLevel.IsNotNil() {
			if loggingLevel.EqualTo("OFF", parser.IgnoreCase) {
				settings.LoggingEnabled = iacTypes.Bool(false, loggingLevel.Metadata())
			} else {
				settings.LoggingEnabled = iacTypes.Bool(true, loggingLevel.Metadata())
			}
		}
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
