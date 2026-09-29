package s3

import (
	iamAdapter "github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func (a *adapter) adaptBucketPolicies() {

	for _, b := range a.modules.GetResourcesByType("aws_s3_bucket_policy") {

		policyAttr := b.GetAttribute("policy")
		if policyAttr.IsNil() {
			continue
		}
		doc, err := iamAdapter.ParsePolicyFromAttr(policyAttr, b, a.modules)
		if err != nil {
			continue
		}

		policy := iam.Policy{
			Metadata: policyAttr.GetMetadata(),
			Name:     iacTypes.StringDefault("", b.GetMetadata()),
			Document: *doc,
			Builtin:  iacTypes.Bool(false, b.GetMetadata()),
		}

		var bucketName string
		bucketAttr := b.GetAttribute("bucket")

		if bucketAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, b); err == nil {
				if bucket, ok := a.bucketMap[referencedBlock.ID()]; ok {
					bucket.BucketPolicies = append(bucket.BucketPolicies, policy)
					a.bucketMap[referencedBlock.ID()] = bucket
					continue
				}
			}
		}

		if bucketAttr.IsString() {
			bucketName = bucketAttr.Value().AsString()
			for id, bucket := range a.bucketMap {
				if bucket.Name.EqualTo(bucketName) {
					bucket.BucketPolicies = append(bucket.BucketPolicies, policy)
					a.bucketMap[id] = bucket
					break
				}
			}
		}
	}
}
