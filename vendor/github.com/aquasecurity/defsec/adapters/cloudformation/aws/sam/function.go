package sam

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/iam"
	"github.com/aquasecurity/defsec/providers/aws/sam"
	"github.com/liamg/iamgo"
)

func getFunctions(cfFile parser.FileContext) (functions []sam.Function) {

	functionResources := cfFile.GetResourceByType("AWS::Serverless::Function")
	for _, r := range functionResources {
		function := sam.Function{
			Metadata:     r.Metadata(),
			FunctionName: r.GetStringProperty("FunctionName"),
			Tracing:      r.GetStringProperty("Tracing", sam.TracingModePassThrough),
		}

		setFunctionPolicies(r, &function)
		functions = append(functions, function)
	}

	return functions
}

func setFunctionPolicies(r *parser.Resource, function *sam.Function) {
	policies := r.GetProperty("Policies")
	if policies.IsNotNil() {
		if policies.IsString() {
			function.ManagedPolicies = append(function.ManagedPolicies, policies.AsStringValue())
		} else if policies.IsList() {
			for _, property := range policies.AsList() {
				if property.IsMap() {
					parsed, err := iamgo.Parse(property.GetJsonBytes())
					if err != nil {
						continue
					}
					policy := iam.Policy{
						Document: iam.Document{
							Parsed:   *parsed,
							Metadata: property.Metadata(),
						},
					}
					function.Policies = append(function.Policies, policy)
				} else {
					function.ManagedPolicies = append(function.ManagedPolicies, property.AsStringValue())
				}

			}
		}
	}
}
