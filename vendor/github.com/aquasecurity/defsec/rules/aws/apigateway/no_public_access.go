package apigateway

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/providers/aws/apigateway"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0004",
		Provider:    providers.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "no-public-access",
		Summary:     "No unauthorized access to API Gateway methods",
		Impact:      "API gateway methods can be accessed without authorization.",
		Resolution:  "Use and authorization method or require API Key",
		Explanation: `API Gateway methods should generally be protected by authorization or api key. OPTION verb calls can be used without authorization`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, api := range s.AWS.APIGateway.APIs {
			if api.IsUnmanaged() || api.ProtocolType.NotEqualTo(apigateway.ProtocolTypeREST) {
				continue
			}
			for _, method := range api.RESTMethods {
				if method.HTTPMethod.EqualTo("OPTION") {
					continue
				}
				if method.APIKeyRequired.IsTrue() {
					continue
				}
				if method.AuthorizationType.EqualTo(apigateway.AuthorizationNone) {
					results.Add(
						"Authorization is not enabled for this method.",
						method.AuthorizationType,
					)
				} else {
					results.AddPassed(&method)
				}
			}
		}
		return
	},
)
