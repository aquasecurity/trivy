package iam

import (
	"github.com/aquasecurity/iamgo"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func parsePolicy(policyBlock *terraform.Block, modules terraform.Modules) (iam.Policy, error) {
	nameAttr := policyBlock.GetAttribute("name")
	policy := iam.Policy{
		Metadata: policyBlock.GetMetadata(),
		Name:     nameAttr.AsStringValueOrDefault("", policyBlock),
		Document: iam.Document{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Parsed:   iamgo.Document{},
			IsOffset: false,
			HasRefs:  false,
		},
		Builtin: iacTypes.Bool(false, policyBlock.GetMetadata()),
	}

	if policyBlock.Type() == "data" && policyBlock.TypeLabel() == "aws_iam_policy" &&
		nameAttr.IsString() {
		doc, exists := awsManagedPolicies[nameAttr.Value().AsString()]
		if exists {
			policy.Document = iam.Document{
				Metadata: nameAttr.GetMetadata(),
				Parsed:   doc,
			}
			return policy, nil
		}
	}

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
		attr := resource.GetAttribute("policy_arn")
		if attr.IsNil() {
			return nil
		}

		if attr.IsString() {
			arn := attr.Value().AsString()
			if doc, ok := awsManagedPolicies[arn]; ok {
				if block, err := modules.GetReferencedBlock(attr, resource); err == nil {
					meta := block.GetMetadata()
					if arnAttr := block.GetAttribute("arn"); arnAttr.IsNotNil() {
						meta = arnAttr.GetMetadata()
					}
					return &iam.Policy{
						Metadata: block.GetMetadata(),
						Document: iam.Document{
							Metadata: meta,
							Parsed:   doc,
						},
					}
				}
				return &iam.Policy{
					Metadata: resource.GetMetadata(),
					Document: iam.Document{
						Metadata: attr.GetMetadata(),
						Parsed:   doc,
					},
				}
			}
		}

		if block, err := modules.GetReferencedBlock(attr, resource); err == nil {
			return findPolicy(modules)(block)
		}

		return nil
	}
}

var awsManagedPolicies = map[string]iamgo.Document{
	// https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonS3FullAccess.html
	"arn:aws:iam::aws:policy/AmazonS3FullAccess": s3FullAccessPolicyDocument,
	"AmazonS3FullAccess":                         s3FullAccessPolicyDocument,
}

var s3FullAccessPolicyDocument = iamgo.NewPolicyBuilder().
	WithVersion("2012-10-17").
	WithStatement(
		iamgo.NewStatementBuilder().
			WithEffect("Allow").
			WithActions([]string{"s3:*", "s3-object-lambda:*"}).
			WithResources([]string{"*"}).
			Build(),
	).
	Build()
