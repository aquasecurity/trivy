package sam

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/sam"
)

func getHttpApis(cfFile parser.FileContext) (apis []sam.HttpAPI) {

	apiResources := cfFile.GetResourceByType("AWS::Serverless::HttpApi")
	for _, r := range apiResources {
		api := sam.HttpAPI{
			Metadata:             r.Metadata(),
			Name:                 r.GetStringProperty("Name", ""),
			DomainConfiguration:  getDomainConfiguration(r),
			AccessLogging:        getAccessLogging(r),
			DefaultRouteSettings: getRouteSettings(r),
		}

		apis = append(apis, api)
	}

	return apis
}

func getRouteSettings(r *parser.Resource) sam.RouteSettings {

	route := r.GetProperty("DefaultRouteSettings")
	if route.IsNil() {
		return sam.RouteSettings{
			Metadata:               r.Metadata(),
			LoggingEnabled:         types.BoolDefault(false, r.Metadata()),
			DataTraceEnabled:       types.BoolDefault(false, r.Metadata()),
			DetailedMetricsEnabled: types.BoolDefault(false, r.Metadata()),
		}
	}

	return sam.RouteSettings{
		Metadata:               route.Metadata(),
		LoggingEnabled:         route.GetBoolProperty("LoggingLevel"),
		DataTraceEnabled:       route.GetBoolProperty("DataTraceEnabled"),
		DetailedMetricsEnabled: route.GetBoolProperty("DetailedMetricsEnabled"),
	}
}
