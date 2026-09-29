package apigateway

import (
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

func adaptAPIsV1(fctx parser.FileContext) []v1.API {
	var apis []v1.API

	stages := make(map[string]*parser.Resource)
	for _, stageResource := range fctx.GetResourcesByType("AWS::ApiGateway::Stage") {
		restApiID := stageResource.GetStringProperty("RestApiId")
		if restApiID.IsEmpty() {
			continue
		}

		stages[restApiID.Value()] = stageResource
	}

	resources := make(map[string]*parser.Resource)
	for _, resource := range fctx.GetResourcesByType("AWS::ApiGateway::Resource") {
		restApiID := resource.GetStringProperty("RestApiId")
		if restApiID.IsEmpty() {
			continue
		}

		resources[restApiID.Value()] = resource
	}

	for _, apiResource := range fctx.GetResourcesByType("AWS::ApiGateway::RestApi") {

		api := v1.API{
			Metadata: apiResource.Metadata(),
			Name:     apiResource.GetStringProperty("Name"),
		}

		if stageResource, exists := stages[apiResource.ID()]; exists {
			stage := v1.Stage{
				Metadata:           stageResource.Metadata(),
				Name:               stageResource.GetStringProperty("StageName"),
				XRayTracingEnabled: stageResource.GetBoolProperty("TracingEnabled"),
			}

			if logSetting := stageResource.GetProperty("AccessLogSetting"); logSetting.IsNotNil() {
				stage.AccessLogging = v1.AccessLogging{
					Metadata:              logSetting.Metadata(),
					CloudwatchLogGroupARN: logSetting.GetStringProperty("DestinationArn"),
				}
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

			api.Stages = append(api.Stages, stage)
		}

		if resource, exists := resources[apiResource.ID()]; exists {
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

			api.Resources = append(api.Resources, res)
		}

		apis = append(apis, api)
	}

	return apis
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
