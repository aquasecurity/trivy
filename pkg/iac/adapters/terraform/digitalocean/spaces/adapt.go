package spaces

import (
	"github.com/google/uuid"

	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean/spaces"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) spaces.Spaces {
	return spaces.Spaces{
		Buckets: adaptBuckets(modules),
	}
}

func adaptBuckets(modules terraform.Modules) []spaces.Bucket {
	bucketMap := make(map[string]spaces.Bucket)
	for _, module := range modules {

		for _, block := range module.GetResourcesByType("digitalocean_spaces_bucket") {

			bucket := spaces.Bucket{
				Metadata:     block.GetMetadata(),
				Name:         block.GetAttribute("name").AsStringValueOrDefault("", block),
				Objects:      nil,
				ACL:          block.GetAttribute("acl").AsStringValueOrDefault("public-read", block),
				ForceDestroy: block.GetAttribute("force_destroy").AsBoolValueOrDefault(false, block),
				Versioning: spaces.Versioning{
					Metadata: block.GetMetadata(),
					Enabled:  iacTypes.BoolDefault(false, block.GetMetadata()),
				},
			}

			if versioning := block.GetBlock("versioning"); versioning.IsNotNil() {
				bucket.Versioning = spaces.Versioning{
					Metadata: versioning.GetMetadata(),
					Enabled:  versioning.GetAttribute("enabled").AsBoolValueOrDefault(false, versioning),
				}
			}
			bucketMap[block.ID()] = bucket
		}
		for _, block := range module.GetResourcesByType("digitalocean_spaces_bucket_object") {
			object := spaces.Object{
				Metadata: block.GetMetadata(),
				ACL:      block.GetAttribute("acl").AsStringValueOrDefault("private", block),
			}
			bucketName := block.GetAttribute("bucket")
			var found bool
			if bucketName.IsString() {
				for i, bucket := range bucketMap {
					if bucket.Name.Value() == bucketName.Value().AsString() {
						bucket.Objects = append(bucket.Objects, object)
						bucketMap[i] = bucket
						found = true
						break
					}
				}
				if found {
					continue
				}
			} else if bucketName.IsNotNil() {
				if referencedBlock, err := module.GetReferencedBlock(bucketName, block); err == nil {
					if bucket, ok := bucketMap[referencedBlock.ID()]; ok {
						bucket.Objects = append(bucket.Objects, object)
						bucketMap[referencedBlock.ID()] = bucket
						continue
					}
				}
			}
			bucketMap[uuid.NewString()] = spaces.Bucket{
				Metadata: iacTypes.NewUnmanagedMetadata(),
				Name:     iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
				Objects: []spaces.Object{
					object,
				},
				ACL:          iacTypes.StringDefault("private", iacTypes.NewUnmanagedMetadata()),
				ForceDestroy: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				Versioning: spaces.Versioning{
					Metadata: block.GetMetadata(),
					Enabled:  iacTypes.BoolDefault(false, block.GetMetadata()),
				},
			}
		}
	}

	var buckets []spaces.Bucket
	for _, bucket := range bucketMap {
		buckets = append(buckets, bucket)
	}
	return buckets
}
