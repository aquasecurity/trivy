package lambda

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/lambda"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getFunctions(ctx parser2.FileContext) (functions []lambda.Function) {

	functionResources := ctx.GetResourcesByType("AWS::Lambda::Function")

	for _, r := range functionResources {

		function := lambda.Function{
			Metadata: r.Metadata(),
			Tracing: lambda.Tracing{
				Metadata: r.Metadata(),
				Mode:     types.StringDefault("PassThrough", r.Metadata()),
			},
			Permissions: getPermissions(r, ctx),
		}

		if prop := r.GetProperty("TracingConfig"); prop.IsNotNil() {
			function.Tracing = lambda.Tracing{
				Metadata: prop.Metadata(),
				Mode:     prop.GetStringProperty("Mode", "PassThrough"),
			}
		}

		functions = append(functions, function)
	}

	return functions
}

func getPermissions(funcR *parser2.Resource, ctx parser2.FileContext) (perms []lambda.Permission) {

	permissionResources := ctx.GetResourcesByType("AWS::Lambda::Permission")

	for _, r := range permissionResources {
		if prop := r.GetStringProperty("FunctionName"); prop.EqualTo(funcR.ID()) {
			perm := lambda.Permission{
				Metadata:  r.Metadata(),
				Principal: r.GetStringProperty("Principal"),
				SourceARN: r.GetStringProperty("SourceArn"),
			}
			perms = append(perms, perm)
		}
	}

	return perms
}
