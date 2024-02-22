package storage

import (
	iam2 "github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/google/iam"
	iamTypes "github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
)

type parentedBinding struct {
	blockID       string
	bucketID      string
	bucketBlockID string
	bindings      []iamTypes.Binding
}

const GoogleStorageBucket = "google_storage_bucket"

type parentedMember struct {
	blockID       string
	bucketID      string
	bucketBlockID string
	member        iamTypes.Member
}

func (a *adapter) adaptBindings() {

	for _, iamBlock := range a.modules.GetResourcesByType("google_storage_bucket_iam_policy") {
		var parented parentedBinding
		parented.blockID = iamBlock.ID()

		bucketAttr := iamBlock.GetAttribute("bucket")
		if bucketAttr.IsString() {
			parented.bucketID = bucketAttr.Value().AsString()
		}

		if refBlock, err := a.modules.GetReferencedBlock(bucketAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == GoogleStorageBucket {
				parented.bucketBlockID = refBlock.ID()
			}
		}

		policyAttr := iamBlock.GetAttribute("policy_data")
		if policyAttr.IsNil() {
			continue
		}

		policyBlock, err := a.modules.GetReferencedBlock(policyAttr, iamBlock)
		if err != nil {
			continue
		}

		parented.bindings = iam2.ParsePolicyBlock(policyBlock)
		a.bindings = append(a.bindings, parented)
	}

	for _, iamBlock := range a.modules.GetResourcesByType("google_storage_bucket_iam_binding") {

		var parented parentedBinding
		parented.blockID = iamBlock.ID()
		parented.bindings = []iamTypes.Binding{iam2.AdaptBinding(iamBlock, a.modules)}

		bucketAttr := iamBlock.GetAttribute("bucket")
		if bucketAttr.IsString() {
			parented.bucketID = bucketAttr.Value().AsString()
		}

		if refBlock, err := a.modules.GetReferencedBlock(bucketAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == GoogleStorageBucket {
				parented.bucketBlockID = refBlock.ID()
			}
		}

		a.bindings = append(a.bindings, parented)
	}
}

func (a *adapter) adaptMembers() {

	for _, iamBlock := range a.modules.GetResourcesByType("google_storage_bucket_iam_member") {

		var parented parentedMember
		parented.blockID = iamBlock.ID()
		parented.member = iam2.AdaptMember(iamBlock, a.modules)

		bucketAttr := iamBlock.GetAttribute("bucket")
		if bucketAttr.IsString() {
			parented.bucketID = bucketAttr.Value().AsString()
		}

		if refBlock, err := a.modules.GetReferencedBlock(bucketAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == GoogleStorageBucket {
				parented.bucketBlockID = refBlock.ID()
			}
		}

		a.members = append(a.members, parented)
	}

}
