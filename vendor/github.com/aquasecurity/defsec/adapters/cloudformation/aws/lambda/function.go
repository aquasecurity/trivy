package lambda

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/lambda"
)

func getFunctions(ctx parser.FileContext) (functions []lambda.Function) {

	functionResources := ctx.GetResourceByType("AWS::Lambda::Function")

	for _, r := range functionResources {

		function := lambda.Function{
			Metadata: r.Metadata(),
			Tracing: lambda.Tracing{
				Mode: r.GetStringProperty("TracingConfig.Mode"),
			},
			Permissions: getPermissions(r, ctx),
		}

		functions = append(functions, function)
	}

	return functions
}

func getPermissions(funcR *parser.Resource, ctx parser.FileContext) (perms []lambda.Permission) {

	permissionResources := ctx.GetResourceByType("AWS::Lambda::Permission")

	for _, r := range permissionResources {
		if r.GetStringProperty("FunctionName").EqualTo(funcR.ID()) {
			perm := lambda.Permission{
				Principal: r.GetStringProperty("Principal"),
				SourceARN: r.GetStringProperty("SourceArn"),
			}

			perms = append(perms, perm)
		}
	}

	return perms
}
