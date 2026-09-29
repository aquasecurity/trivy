package apigateway

import (
	v2 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptAPIsV2(cfFile parser.FileContext) (apis []v2.API) {

	apiResources := cfFile.GetResourcesByType("AWS::ApiGatewayV2::Api")
	for _, apiRes := range apiResources {
		api := v2.API{
			Metadata:     apiRes.Metadata(),
			Name:         apiRes.GetStringProperty("Name"),
			ProtocolType: apiRes.GetStringProperty("ProtocolType"),
			Stages:       getStages(apiRes.ID(), cfFile),
		}
		apis = append(apis, api)
	}

	return apis
}

func getStages(apiId string, cfFile parser.FileContext) []v2.Stage {
	var apiStages []v2.Stage

	stageResources := cfFile.GetResourcesByType("AWS::ApiGatewayV2::Stage")
	for _, r := range stageResources {
		stageApiId := r.GetStringProperty("ApiId")
		if stageApiId.Value() != apiId {
			continue
		}

		s := v2.Stage{
			Metadata:      r.Metadata(),
			Name:          r.GetStringProperty("StageName"),
			AccessLogging: getAccessLogging(r),
		}
		apiStages = append(apiStages, s)
	}

	return apiStages
}

func getAccessLogging(r *parser.Resource) v2.AccessLogging {

	loggingProp := r.GetProperty("AccessLogSettings")
	if loggingProp.IsNil() {
		return v2.AccessLogging{
			Metadata:              r.Metadata(),
			CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
		}
	}

	destinationProp := r.GetProperty("AccessLogSettings.DestinationArn")

	if destinationProp.IsNil() {
		return v2.AccessLogging{
			Metadata:              loggingProp.Metadata(),
			CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
		}
	}
	return v2.AccessLogging{
		Metadata:              destinationProp.Metadata(),
		CloudwatchLogGroupARN: destinationProp.AsStringValue(),
	}
}

func adaptDomainNamesV2(fctx parser.FileContext) []v2.DomainName {
	var domainNames []v2.DomainName

	for _, domainNameResource := range fctx.GetResourcesByType("AWS::ApiGateway::DomainName") {

		domainName := v2.DomainName{
			Metadata:       domainNameResource.Metadata(),
			Name:           domainNameResource.GetStringProperty("DomainName"),
			SecurityPolicy: domainNameResource.GetStringProperty("SecurityPolicy"),
		}

		if domainNameCfgs := domainNameResource.GetProperty("DomainNameConfigurations"); domainNameCfgs.IsList() {
			for _, domainNameCfg := range domainNameCfgs.AsList() {
				domainName.SecurityPolicy = domainNameCfg.GetStringProperty("SecurityPolicy")
			}
		}

		domainNames = append(domainNames, domainName)
	}

	return domainNames
}
