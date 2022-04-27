package iam

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/providers/aws/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
	"github.com/liamg/iamgo"
)

var CheckNoPolicyWildcards = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0057",
		Provider:    providers.AWSProvider,
		Service:     "iam",
		ShortCode:   "no-policy-wildcards",
		Summary:     "IAM policy should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPolicyWildcardsGoodExamples,
			BadExamples:         terraformNoPolicyWildcardsBadExamples,
			Links:               terraformNoPolicyWildcardsLinks,
			RemediationMarkdown: terraformNoPolicyWildcardsRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoPolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoPolicyWildcardsBadExamples,
			Links:               cloudFormationNoPolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoPolicyWildcardsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, policy := range s.AWS.IAM.Policies {
			results = checkPolicy(policy.Document, results)
		}
		for _, group := range s.AWS.IAM.Groups {
			for _, policy := range group.Policies {
				results = checkPolicy(policy.Document, results)
			}
		}
		for _, user := range s.AWS.IAM.Users {
			for _, policy := range user.Policies {
				results = checkPolicy(policy.Document, results)
			}
		}
		for _, role := range s.AWS.IAM.Roles {
			for _, policy := range role.Policies {
				results = checkPolicy(policy.Document, results)
			}
		}
		return results
	},
)

func checkPolicy(src iam.Document, results rules.Results) rules.Results {
	statements, _ := src.Parsed.Statements()
	for _, statement := range statements {
		results = checkStatement(src, statement, results)
	}
	return results
}

//nolint
func checkStatement(src iam.Document, statement iamgo.Statement, results rules.Results) rules.Results {
	effect, _ := statement.Effect()
	if effect != iamgo.EffectAllow {
		return results
	}

	actions, r := statement.Actions()
	for _, action := range actions {
		if strings.Contains(action, "*") {
			results.Add(
				fmt.Sprintf(
					"IAM policy document uses wildcarded action '%s'",
					actions[0],
				),
				src.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			results.AddPassed(src)
		}
	}

	resources, r := statement.Resources()
	for _, resource := range resources {
		if strings.Contains(resource, "*") {
			if allowed, action := iam.IsWildcardAllowed(actions...); !allowed {
				if strings.HasSuffix(resource, "/*") && strings.HasPrefix(resource, "arn:aws:s3") {
					continue
				}
				results.Add(
					fmt.Sprintf("IAM policy document uses sensitive action '%s' on wildcarded resource '%s'", action, resources[0]),
					src.MetadataFromIamGo(statement.Range(), r),
				)
			} else {
				results.AddPassed(src)
			}
		} else {
			results.AddPassed(src)
		}
	}
	principals, _ := statement.Principals()
	if all, r := principals.All(); all {
		results.Add(
			"IAM policy document uses wildcarded principal.",
			src.MetadataFromIamGo(statement.Range(), r),
		)
	}
	aws, r := principals.AWS()
	for _, principal := range aws {
		if strings.Contains(principal, "*") {
			results.Add(
				"IAM policy document uses wildcarded principal.",
				src.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			results.AddPassed(src)
		}
	}

	return results
}
