package sam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sam"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getHttpApis(cfFile parser.FileContext) (apis []sam.HttpAPI) {

	apiResources := cfFile.GetResourcesByType("AWS::Serverless::HttpApi")
	for _, r := range apiResources {
		api := sam.HttpAPI{
			Metadata:             r.Metadata(),
			Name:                 r.GetStringProperty("Name", ""),
			DomainConfiguration:  getDomainConfiguration(r),
			AccessLogging:        getAccessLoggingV2(r),
			DefaultRouteSettings: getRouteSettings(r),
		}

		apis = append(apis, api)
	}

	return apis
}

func getAccessLoggingV2(r *parser.Resource) sam.AccessLogging {

	logging := sam.AccessLogging{
		Metadata:              r.Metadata(),
		CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
	}

	if access := r.GetProperty("AccessLogSettings"); access.IsNotNil() {
		logging = sam.AccessLogging{
			Metadata:              access.Metadata(),
			CloudwatchLogGroupARN: access.GetStringProperty("DestinationArn", ""),
		}
	}

	return logging
}

func getRouteSettings(r *parser.Resource) sam.RouteSettings {

	routeSettings := sam.RouteSettings{
		Metadata:               r.Metadata(),
		LoggingEnabled:         types.BoolDefault(false, r.Metadata()),
		DataTraceEnabled:       types.BoolDefault(false, r.Metadata()),
		DetailedMetricsEnabled: types.BoolDefault(false, r.Metadata()),
	}

	if route := r.GetProperty("DefaultRouteSettings"); route.IsNotNil() {
		routeSettings = sam.RouteSettings{
			Metadata: route.Metadata(),
			// TODO: LoggingLevel is string
			LoggingEnabled:         route.GetBoolProperty("LoggingLevel"),
			DataTraceEnabled:       route.GetBoolProperty("DataTraceEnabled"),
			DetailedMetricsEnabled: route.GetBoolProperty("DetailedMetricsEnabled"),
		}
	}

	return routeSettings

}
