package s3

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
)

func (a *adapter) adaptPublicAccessBlocks() {

	for _, b := range a.modules.GetResourcesByType("aws_s3_bucket_public_access_block") {

		pba := s3.PublicAccessBlock{
			Metadata:              b.GetMetadata(),
			BlockPublicACLs:       b.GetAttribute("block_public_acls").AsBoolValueOrDefault(false, b),
			BlockPublicPolicy:     b.GetAttribute("block_public_policy").AsBoolValueOrDefault(false, b),
			IgnorePublicACLs:      b.GetAttribute("ignore_public_acls").AsBoolValueOrDefault(false, b),
			RestrictPublicBuckets: b.GetAttribute("restrict_public_buckets").AsBoolValueOrDefault(false, b),
		}

		var bucketName string
		bucketAttr := b.GetAttribute("bucket")
		if bucketAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, b); err == nil {
				if bucket, ok := a.bucketMap[referencedBlock.ID()]; ok {
					bucket.PublicAccessBlock = &pba
					a.bucketMap[referencedBlock.ID()] = bucket
					continue
				}
			}
		}
		if bucketAttr.IsString() {
			bucketName = bucketAttr.Value().AsString()
			for id, bucket := range a.bucketMap {
				if bucketAttr.Equals(id) || bucket.Name.EqualTo(bucketName) {
					bucket.PublicAccessBlock = &pba
					a.bucketMap[id] = bucket
					continue
				}
			}
		}
	}
}
