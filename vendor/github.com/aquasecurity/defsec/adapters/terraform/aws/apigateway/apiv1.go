package apigateway

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/apigateway"
)

func adaptAPIMethodsV1(modules terraform.Modules, apiBlock *terraform.Block) []apigateway.RESTMethod {
	var methods []apigateway.RESTMethod
	for _, methodBlock := range modules.GetReferencingResources(apiBlock, "aws_api_gateway_method", "rest_api_id") {
		var method apigateway.RESTMethod
		method.HTTPMethod = methodBlock.GetAttribute("http_method").AsStringValueOrDefault("", methodBlock)
		method.AuthorizationType = methodBlock.GetAttribute("authorization").AsStringValueOrDefault("", methodBlock)
		method.APIKeyRequired = methodBlock.GetAttribute("api_key_required").AsBoolValueOrDefault(false, methodBlock)
		methods = append(methods, method)
	}
	return methods
}

func adaptAPIsV1(modules terraform.Modules) []apigateway.API {

	var apis []apigateway.API
	apiStageIDs := modules.GetChildResourceIDMapByType("aws_api_gateway_stage")

	for _, apiBlock := range modules.GetResourcesByType("aws_api_gateway_rest_api") {
		var api apigateway.API
		api.Metadata = apiBlock.GetMetadata()
		api.Version = types.Int(1, apiBlock.GetMetadata())
		api.Name = apiBlock.GetAttribute("name").AsStringValueOrDefault("", apiBlock)
		api.ProtocolType = types.StringDefault(apigateway.ProtocolTypeREST, apiBlock.GetMetadata())
		api.RESTMethods = adaptAPIMethodsV1(modules, apiBlock)

		var defaultCacheEncryption = types.BoolDefault(false, api.Metadata)
		for _, methodSettings := range modules.GetReferencingResources(apiBlock, "aws_api_gateway_method_settings", "rest_api_id") {
			if settings := methodSettings.GetBlock("settings"); settings.IsNotNil() {
				defaultCacheEncryption = settings.GetAttribute("cache_data_encrypted").AsBoolValueOrDefault(false, settings)
			}
		}

		for _, stageBlock := range modules.GetReferencingResources(apiBlock, "aws_api_gateway_stage", "rest_api_id") {
			apiStageIDs.Resolve(stageBlock.ID())
			stage := adaptStageV1(stageBlock, defaultCacheEncryption, modules)

			api.Stages = append(api.Stages, stage)
		}

		apis = append(apis, api)
	}

	orphanResources := modules.GetResourceByIDs(apiStageIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := apigateway.API{
			Metadata: types.NewUnmanagedMetadata(),
		}
		for _, stage := range orphanResources {
			orphanage.Stages = append(orphanage.Stages, adaptStageV1(stage, types.BoolDefault(false, stage.GetMetadata()), modules))
		}
		apis = append(apis, orphanage)
	}

	return apis
}

func adaptStageV1(stageBlock *terraform.Block, defaultCacheEncryption types.BoolValue, modules terraform.Modules) apigateway.Stage {
	stage := apigateway.Stage{
		Metadata: stageBlock.GetMetadata(),
		Version:  types.Int(1, stageBlock.GetMetadata()),
		RESTMethodSettings: apigateway.RESTMethodSettings{
			Metadata:           stageBlock.GetMetadata(),
			CacheDataEncrypted: defaultCacheEncryption,
		},
		AccessLogging: apigateway.AccessLogging{
			Metadata:              stageBlock.GetMetadata(),
			CloudwatchLogGroupARN: types.StringDefault("", stageBlock.GetMetadata()),
		},
	}
	for _, methodSettings := range modules.GetReferencingResources(stageBlock, "aws_api_gateway_method_settings", "stage_name") {
		stage.RESTMethodSettings.Metadata = methodSettings.GetMetadata()
		if settings := methodSettings.GetBlock("settings"); settings.IsNotNil() {
			if encrypted := settings.GetAttribute("cache_data_encrypted"); encrypted.IsNotNil() {
				stage.RESTMethodSettings.CacheDataEncrypted = settings.GetAttribute("cache_data_encrypted").AsBoolValueOrDefault(false, settings)
			}
		}
	}

	stage.Name = stageBlock.GetAttribute("stage_name").AsStringValueOrDefault("", stageBlock)
	if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
		stage.AccessLogging.Metadata = accessLogging.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
	} else {
		stage.AccessLogging.Metadata = stageBlock.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = types.StringDefault("", stageBlock.GetMetadata())
	}

	stage.XRayTracingEnabled = stageBlock.GetAttribute("xray_tracing_enabled").AsBoolValueOrDefault(false, stageBlock)
	return stage
}
