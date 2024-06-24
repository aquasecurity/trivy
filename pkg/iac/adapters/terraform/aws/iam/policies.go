package iam

import (
	"github.com/liamg/iamgo"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func parsePolicy(policyBlock *terraform.Block, modules terraform.Modules) (iam.Policy, error) {
	policy := iam.Policy{
		Metadata: policyBlock.GetMetadata(),
		Name:     policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock),
		Document: iam.Document{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Parsed:   iamgo.Document{},
			IsOffset: false,
			HasRefs:  false,
		},
		Builtin: iacTypes.Bool(false, policyBlock.GetMetadata()),
	}
	var err error
	doc, err := ParsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, modules)
	if err != nil {
		return policy, err
	}
	policy.Document = *doc
	return policy, nil
}

func adaptPolicies(modules terraform.Modules) (policies []iam.Policy) {
	for _, policyBlock := range modules.GetResourcesByType("aws_iam_policy") {
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		policies = append(policies, policy)
	}
	return
}

// applyForDependentResource returns the result of
// applying the function to the dependent block from the parent block and true
// if the parent block was found.
//
//	resource "aws_s3_bucket" "this" {
//	  bucket = ...
//	  ...
//	}
//
//	resource "aws_s3_bucket_logging" "this" {
//	  bucket = aws_s3_bucket.this.id
//	  ...
//	}
func applyForDependentResource[T any](
	modules terraform.Modules,
	refBlockID string,
	refAttrName string,
	dependentResourceType string,
	dependentAttrName string,
	fn func(resource *terraform.Block) T,
) (T, bool) {
	for _, resource := range modules.GetResourcesByType(dependentResourceType) {
		relatedAttr := resource.GetAttribute(dependentAttrName)
		if relatedAttr.IsNil() {
			continue
		}

		refBlock, err := modules.GetBlockById(refBlockID)
		if err != nil {
			continue
		}

		if isDependentBlock(refBlock, refAttrName, relatedAttr) {
			return fn(resource), true
		}
	}
	var res T
	return res, false
}

func isDependentBlock(refBlock *terraform.Block, refAttrName string, relatedAttr *terraform.Attribute) bool {
	refAttr := refBlock.GetAttribute(refAttrName).AsStringValueOrDefault("", refBlock).Value()
	return relatedAttr.Equals(refBlock.ID()) || relatedAttr.Equals(refAttr) || relatedAttr.ReferencesBlock(refBlock)
}

func findPolicy(modules terraform.Modules) func(resource *terraform.Block) *iam.Policy {
	return func(resource *terraform.Block) *iam.Policy {
		policy, err := parsePolicy(resource, modules)
		if err != nil {
			return nil
		}
		return &policy
	}
}

func findAttachmentPolicy(modules terraform.Modules) func(resource *terraform.Block) *iam.Policy {
	return func(resource *terraform.Block) *iam.Policy {
		policyAttr := resource.GetAttribute("policy_arn")
		if policyAttr.IsNil() {
			return nil
		}
		policyBlock, err := modules.GetReferencedBlock(policyAttr, resource)
		if err != nil {
			return nil
		}
		return findPolicy(modules)(policyBlock)
	}
}
