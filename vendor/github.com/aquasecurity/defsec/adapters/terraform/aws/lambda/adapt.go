package lambda

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/lambda"
)

func Adapt(modules terraform.Modules) lambda.Lambda {

	adapter := adapter{
		permissionIDs: modules.GetChildResourceIDMapByType("aws_lambda_permission"),
	}

	return lambda.Lambda{
		Functions: adapter.adaptFunctions(modules),
	}
}

type adapter struct {
	permissionIDs terraform.ResourceIDResolutions
}

func (a *adapter) adaptFunctions(modules terraform.Modules) []lambda.Function {

	var functions []lambda.Function
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_lambda_function") {
			functions = append(functions, a.adaptFunction(resource, modules))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.permissionIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := lambda.Function{
			Metadata: types.NewUnmanagedMetadata(),
			Tracing: lambda.Tracing{
				Metadata: types.NewUnmanagedMetadata(),
				Mode:     types.StringDefault("", types.NewUnmanagedMetadata()),
			},
			Permissions: nil,
		}
		for _, permission := range orphanResources {
			orphanage.Permissions = append(orphanage.Permissions, a.adaptPermission(permission))
		}
		functions = append(functions, orphanage)
	}

	return functions
}

func (a *adapter) adaptFunction(function *terraform.Block, modules terraform.Modules) lambda.Function {
	return lambda.Function{
		Metadata:    function.GetMetadata(),
		Tracing:     a.adaptTracing(function),
		Permissions: a.adaptPermissions(modules),
	}
}

func (a *adapter) adaptTracing(function *terraform.Block) lambda.Tracing {
	if tracingConfig := function.GetBlock("tracing_config"); tracingConfig.IsNotNil() {
		return lambda.Tracing{
			Metadata: tracingConfig.GetMetadata(),
			Mode:     tracingConfig.GetAttribute("mode").AsStringValueOrDefault("", tracingConfig),
		}
	}

	return lambda.Tracing{
		Metadata: function.GetMetadata(),
		Mode:     types.StringDefault("", function.GetMetadata()),
	}
}

func (a *adapter) adaptPermissions(modules terraform.Modules) []lambda.Permission {
	var permissions []lambda.Permission
	for _, module := range modules {
		for _, p := range module.GetResourcesByType("aws_lambda_permission") {
			permissions = append(permissions, a.adaptPermission(p))
		}
	}
	return permissions
}

func (a *adapter) adaptPermission(permission *terraform.Block) lambda.Permission {
	return lambda.Permission{
		Metadata:  permission.GetMetadata(),
		Principal: permission.GetAttribute("principal").AsStringValueOrDefault("", permission),
		SourceARN: permission.GetAttribute("source_arn").AsStringValueOrDefault("", permission),
	}
}
