package lambda

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/lambda"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

func getFunctions(ctx parser.FileContext) (functions []lambda.Function) {

	functionResources := ctx.GetResourcesByType("AWS::Lambda::Function")

	for _, r := range functionResources {

		function := lambda.Function{
			Metadata:    r.Metadata(),
			Permissions: getPermissions(r, ctx),
		}

		if prop := r.GetProperty("TracingConfig"); prop.IsNotNil() {
			function.Tracing = lambda.Tracing{
				Metadata: prop.Metadata(),
				Mode:     prop.GetStringProperty("Mode"),
			}
		}

		functions = append(functions, function)
	}

	return functions
}

func getPermissions(funcR *parser.Resource, ctx parser.FileContext) (perms []lambda.Permission) {

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
