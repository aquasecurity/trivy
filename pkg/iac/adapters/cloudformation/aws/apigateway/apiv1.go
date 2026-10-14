package apigateway

import (
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptAPIsV1(fctx parser.FileContext) []v1.API {
	var apis []v1.API

	for _, apiResource := range fctx.GetResourcesByType("AWS::ApiGateway::RestApi") {
		apis = append(apis, v1.API{
			Metadata:  apiResource.Metadata(),
			Name:      apiResource.GetStringProperty("Name"),
			Stages:    adaptStagesV1(fctx, apiResource.ID()),
			Resources: adaptResourcesV1(fctx, apiResource.ID()),
		})
	}

	return apis
}

func adaptStagesV1(fctx parser.FileContext, apiID string) []v1.Stage {
	var stages []v1.Stage

	for _, stageResource := range fctx.GetResourcesByType("AWS::ApiGateway::Stage") {
		if stageResource.GetStringProperty("RestApiId").Value() != apiID {
			continue
		}

		stage := v1.Stage{
			Metadata:           stageResource.Metadata(),
			Name:               stageResource.GetStringProperty("StageName"),
			AccessLogging:      getAccessLoggingV1(stageResource),
			XRayTracingEnabled: stageResource.GetBoolProperty("TracingEnabled"),
		}

		if methodSettings := stageResource.GetProperty("MethodSettings"); methodSettings.IsList() {
			for _, methodSetting := range methodSettings.AsList() {
				stage.RESTMethodSettings = append(stage.RESTMethodSettings, v1.RESTMethodSettings{
					Metadata:           methodSetting.Metadata(),
					Method:             methodSetting.GetStringProperty("HttpMethod"),
					CacheDataEncrypted: methodSetting.GetBoolProperty("CacheDataEncrypted"),
					CacheEnabled:       methodSetting.GetBoolProperty("CachingEnabled"),
				})
			}
		}

		stages = append(stages, stage)
	}

	return stages
}

func getAccessLoggingV1(r *parser.Resource) v1.AccessLogging {
	loggingProp := r.GetProperty("AccessLogSetting")
	if loggingProp.IsNil() {
		return v1.AccessLogging{
			Metadata:              r.Metadata(),
			CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
		}
	}

	destinationProp := r.GetProperty("AccessLogSetting.DestinationArn")
	if destinationProp.IsNil() {
		return v1.AccessLogging{
			Metadata:              loggingProp.Metadata(),
			CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
		}
	}

	return v1.AccessLogging{
		Metadata:              destinationProp.Metadata(),
		CloudwatchLogGroupARN: destinationProp.AsStringValue(),
	}
}

func adaptResourcesV1(fctx parser.FileContext, apiID string) []v1.Resource {
	var resources []v1.Resource

	for _, resource := range fctx.GetResourcesByType("AWS::ApiGateway::Resource") {
		if resource.GetStringProperty("RestApiId").Value() != apiID {
			continue
		}

		res := v1.Resource{
			Metadata: resource.Metadata(),
		}

		for _, methodResource := range fctx.GetResourcesByType("AWS::ApiGateway::Method") {
			resourceID := methodResource.GetStringProperty("ResourceId")
			// TODO: handle RootResourceId
			if resourceID.Value() != resource.ID() {
				continue
			}

			res.Methods = append(res.Methods, v1.Method{
				Metadata:          methodResource.Metadata(),
				HTTPMethod:        methodResource.GetStringProperty("HttpMethod"),
				AuthorizationType: methodResource.GetStringProperty("AuthorizationType"),
				APIKeyRequired:    methodResource.GetBoolProperty("ApiKeyRequired"),
			})
		}

		resources = append(resources, res)
	}

	return resources
}

func adaptDomainNamesV1(fctx parser.FileContext) []v1.DomainName {
	var domainNames []v1.DomainName

	for _, domainNameResource := range fctx.GetResourcesByType("AWS::ApiGateway::DomainName") {
		domainNames = append(domainNames, v1.DomainName{
			Metadata:       domainNameResource.Metadata(),
			Name:           domainNameResource.GetStringProperty("DomainName"),
			SecurityPolicy: domainNameResource.GetStringProperty("SecurityPolicy"),
		})
	}

	return domainNames
}
