package apigateway

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/apigateway"
)

func getApis(cfFile parser.FileContext) (apis []apigateway.API) {

	apiResources := cfFile.GetResourceByType("AWS::ApiGatewayV2::Api")
	for _, apiRes := range apiResources {
		api := apigateway.API{
			Metadata: apiRes.Metadata(),
			Stages:   getStages(apiRes.ID(), cfFile),
		}
		apis = append(apis, api)
	}

	return apis
}

func getStages(apiId string, cfFile parser.FileContext) []apigateway.Stage {
	var apiStages []apigateway.Stage

	stageResources := cfFile.GetResourceByType("AWS::ApiGatewayV2::Stage")
	for _, r := range stageResources {
		stageApiId := r.GetStringProperty("ApiId")
		if stageApiId.Value() != apiId {
			continue
		}

		s := apigateway.Stage{
			Metadata:      r.Metadata(),
			Name:          r.GetStringProperty("StageName"),
			AccessLogging: getAccessLogging(r),
		}
		apiStages = append(apiStages, s)
	}

	return apiStages
}

func getAccessLogging(r *parser.Resource) apigateway.AccessLogging {

	loggingProp := r.GetProperty("AccessLogSettings")
	if loggingProp.IsNil() {
		return apigateway.AccessLogging{
			Metadata: r.Metadata(),
		}
	}

	destinationProp := r.GetProperty("AccessLogSettings.DestinationArn")

	if destinationProp.IsNil() {
		return apigateway.AccessLogging{
			Metadata:              loggingProp.Metadata(),
			CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
		}
	}
	return apigateway.AccessLogging{
		CloudwatchLogGroupARN: destinationProp.AsStringValue(),
	}
}
