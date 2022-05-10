package vpc

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoDefaultVpc = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0101",
		Provider:    providers.AWSProvider,
		Service:     "vpc",
		ShortCode:   "no-default-vpc",
		Summary:     "AWS best practice to not use the default VPC for workflows",
		Impact:      "The default VPC does not have critical security features applied",
		Resolution:  "Create a non-default vpc for resources to be created in",
		Explanation: `Default VPC does not have a lot of the critical security features that standard VPC comes with, new resources should not be created in the default VPC and it should not be present in the Terraform.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoDefaultVpcGoodExamples,
			BadExamples:         terraformNoDefaultVpcBadExamples,
			Links:               terraformNoDefaultVpcLinks,
			RemediationMarkdown: terraformNoDefaultVpcRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, def := range s.AWS.VPC.DefaultVPCs {
			results.Add(
				"Default VPC is used.",
				&def,
			)
		}
		return
	},
)
