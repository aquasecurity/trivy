package s3

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	iamAdapter "github.com/aquasecurity/trivy/internal/adapters/terraform/aws/iam"
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
			Name:     defsecTypes.StringDefault("", b.GetMetadata()),
			Document: *doc,
			Builtin:  defsecTypes.Bool(false, b.GetMetadata()),
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
