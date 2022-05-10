package iam

import (
	"strings"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers/aws/iam"
)

func sameProvider(b1, b2 *terraform.Block) bool {

	if b1.HasChild("provider") != b2.HasChild("provider") {
		return false
	}

	var provider1, provider2 string
	if providerAttr := b1.GetAttribute("provider"); providerAttr.IsString() {
		provider1 = providerAttr.Value().AsString()
	}
	if providerAttr := b2.GetAttribute("provider"); providerAttr.IsString() {
		provider2 = providerAttr.Value().AsString()
	}
	return strings.EqualFold(provider1, provider2)
}

func parsePolicy(policyBlock *terraform.Block, modules terraform.Modules) (iam.Policy, error) {
	var policy iam.Policy
	policy.Metadata = policyBlock.GetMetadata()
	policy.Name = policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock)
	var err error
	doc, err := parsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, modules)
	if err != nil {
		return policy, err
	}
	policy.Document = *doc
	return policy, nil

}

func adaptPolicies(modules terraform.Modules) (policies []iam.Policy) {
	for _, policyBlock := range modules.GetResourcesByType("aws_iam_policy") {
		var policy iam.Policy
		policy.Name = policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock)
		doc, err := parsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, modules)
		if err != nil {
			continue
		}
		policy.Document = *doc
		policies = append(policies, policy)
	}
	return
}
