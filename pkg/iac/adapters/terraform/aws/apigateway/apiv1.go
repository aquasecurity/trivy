package apigateway

import (
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptAPIResourcesV1(modules terraform.Modules, apiBlock *terraform.Block) []v1.Resource {
	var resources []v1.Resource
	for _, resourceBlock := range modules.GetReferencingResources(apiBlock, "aws_api_gateway_resource", "rest_api_id") {
		method := v1.Resource{
			Metadata: resourceBlock.GetMetadata(),
			Methods:  adaptAPIMethodsV1(modules, resourceBlock),
		}
		resources = append(resources, method)
	}
	return resources
}

func adaptAPIMethodsV1(modules terraform.Modules, resourceBlock *terraform.Block) []v1.Method {
	var methods []v1.Method
	for _, methodBlock := range modules.GetReferencingResources(resourceBlock, "aws_api_gateway_method", "resource_id") {
		method := v1.Method{
			Metadata:          methodBlock.GetMetadata(),
			HTTPMethod:        methodBlock.GetAttribute("http_method").AsStringValueOrDefault("", methodBlock),
			AuthorizationType: methodBlock.GetAttribute("authorization").AsStringValueOrDefault("", methodBlock),
			APIKeyRequired:    methodBlock.GetAttribute("api_key_required").AsBoolValueOrDefault(false, methodBlock),
		}
		methods = append(methods, method)
	}
	return methods
}

func adaptAPIsV1(modules terraform.Modules) []v1.API {

	var apis []v1.API
	apiStageIDs := modules.GetChildResourceIDMapByType("aws_api_gateway_stage")

	for _, apiBlock := range modules.GetResourcesByType("aws_api_gateway_rest_api") {
		api := v1.API{
			Metadata:  apiBlock.GetMetadata(),
			Name:      apiBlock.GetAttribute("name").AsStringValueOrDefault("", apiBlock),
			Stages:    nil,
			Resources: adaptAPIResourcesV1(modules, apiBlock),
		}

		for _, stageBlock := range modules.GetReferencingResources(apiBlock, "aws_api_gateway_stage", "rest_api_id") {
			apiStageIDs.Resolve(stageBlock.ID())
			stage := adaptStageV1(stageBlock, modules)

			api.Stages = append(api.Stages, stage)
		}

		apis = append(apis, api)
	}

	orphanResources := modules.GetResourceByIDs(apiStageIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := v1.API{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Name:     iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
		}
		for _, stage := range orphanResources {
			orphanage.Stages = append(orphanage.Stages, adaptStageV1(stage, modules))
		}
		apis = append(apis, orphanage)
	}

	return apis
}

func adaptStageV1(stageBlock *terraform.Block, modules terraform.Modules) v1.Stage {
	stage := v1.Stage{
		Metadata: stageBlock.GetMetadata(),
		Name:     stageBlock.GetAttribute("name").AsStringValueOrDefault("", stageBlock),
		AccessLogging: v1.AccessLogging{
			Metadata:              stageBlock.GetMetadata(),
			CloudwatchLogGroupARN: iacTypes.StringDefault("", stageBlock.GetMetadata()),
		},
		XRayTracingEnabled: stageBlock.GetAttribute("xray_tracing_enabled").AsBoolValueOrDefault(false, stageBlock),
	}
	for _, methodSettings := range modules.GetReferencingResources(stageBlock, "aws_api_gateway_method_settings", "stage_name") {

		restMethodSettings := v1.RESTMethodSettings{
			Metadata:           methodSettings.GetMetadata(),
			Method:             iacTypes.String("", methodSettings.GetMetadata()),
			CacheDataEncrypted: iacTypes.BoolDefault(false, methodSettings.GetMetadata()),
			CacheEnabled:       iacTypes.BoolDefault(false, methodSettings.GetMetadata()),
		}

		if settings := methodSettings.GetBlock("settings"); settings.IsNotNil() {
			if encrypted := settings.GetAttribute("cache_data_encrypted"); encrypted.IsNotNil() {
				restMethodSettings.CacheDataEncrypted = settings.GetAttribute("cache_data_encrypted").AsBoolValueOrDefault(false, settings)
			}
			if encrypted := settings.GetAttribute("caching_enabled"); encrypted.IsNotNil() {
				restMethodSettings.CacheEnabled = settings.GetAttribute("caching_enabled").AsBoolValueOrDefault(false, settings)
			}
		}

		stage.RESTMethodSettings = append(stage.RESTMethodSettings, restMethodSettings)
	}

	stage.Name = stageBlock.GetAttribute("stage_name").AsStringValueOrDefault("", stageBlock)
	if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
		stage.AccessLogging.Metadata = accessLogging.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
	} else {
		stage.AccessLogging.Metadata = stageBlock.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = iacTypes.StringDefault("", stageBlock.GetMetadata())
	}

	return stage
}
