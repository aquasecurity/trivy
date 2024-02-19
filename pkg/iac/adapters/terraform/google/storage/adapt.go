package storage

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/storage"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) storage.Storage {
	return storage.Storage{
		Buckets: (&adapter{modules: modules}).adaptBuckets(),
	}
}

type adapter struct {
	modules    terraform.Modules
	bindings   []parentedBinding
	members    []parentedMember
	bindingMap terraform.ResourceIDResolutions
	memberMap  terraform.ResourceIDResolutions
}

func (a *adapter) adaptBuckets() []storage.Bucket {

	a.bindingMap = a.modules.GetChildResourceIDMapByType("google_storage_bucket_iam_binding", "google_storage_bucket_iam_policy")
	a.memberMap = a.modules.GetChildResourceIDMapByType("google_storage_bucket_iam_member")

	a.adaptMembers()
	a.adaptBindings()

	var buckets []storage.Bucket
	for _, module := range a.modules {
		for _, resource := range module.GetResourcesByType(GoogleStorageBucket) {
			buckets = append(buckets, a.adaptBucketResource(resource))
		}
	}

	orphanage := storage.Bucket{
		Metadata:                       iacTypes.NewUnmanagedMetadata(),
		Name:                           iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
		Location:                       iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
		EnableUniformBucketLevelAccess: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		Members:                        nil,
		Bindings:                       nil,
	}
	for _, orphanedBindingID := range a.bindingMap.Orphans() {
		for _, binding := range a.bindings {
			if binding.blockID == orphanedBindingID {
				orphanage.Bindings = append(orphanage.Bindings, binding.bindings...)
				break
			}
		}
	}
	for _, orphanedMemberID := range a.memberMap.Orphans() {
		for _, member := range a.members {
			if member.blockID == orphanedMemberID {
				orphanage.Members = append(orphanage.Members, member.member)
				break
			}
		}
	}
	if len(orphanage.Bindings) > 0 || len(orphanage.Members) > 0 {
		buckets = append(buckets, orphanage)
	}

	return buckets
}

func (a *adapter) adaptBucketResource(resourceBlock *terraform.Block) storage.Bucket {

	nameAttr := resourceBlock.GetAttribute("name")
	nameValue := nameAttr.AsStringValueOrDefault("", resourceBlock)

	locationAttr := resourceBlock.GetAttribute("location")
	locationValue := locationAttr.AsStringValueOrDefault("", resourceBlock)

	// See https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#uniform_bucket_level_access
	ublaAttr := resourceBlock.GetAttribute("uniform_bucket_level_access")
	ublaValue := ublaAttr.AsBoolValueOrDefault(false, resourceBlock)

	bucket := storage.Bucket{
		Metadata:                       resourceBlock.GetMetadata(),
		Name:                           nameValue,
		Location:                       locationValue,
		EnableUniformBucketLevelAccess: ublaValue,
		Members:                        nil,
		Bindings:                       nil,
		Encryption: storage.BucketEncryption{
			Metadata:          resourceBlock.GetMetadata(),
			DefaultKMSKeyName: iacTypes.StringDefault("", resourceBlock.GetMetadata()),
		},
	}

	if encBlock := resourceBlock.GetBlock("encryption"); encBlock.IsNotNil() {
		bucket.Encryption.Metadata = encBlock.GetMetadata()
		kmsKeyNameAttr := encBlock.GetAttribute("default_kms_key_name")
		bucket.Encryption.DefaultKMSKeyName = kmsKeyNameAttr.AsStringValueOrDefault("", encBlock)
	}

	var name string
	if nameAttr.IsString() {
		name = nameAttr.Value().AsString()
	}

	for _, member := range a.members {
		if member.bucketBlockID == resourceBlock.ID() {
			bucket.Members = append(bucket.Members, member.member)
			a.memberMap.Resolve(member.blockID)
			continue
		}
		if name != "" && name == member.bucketID {
			bucket.Members = append(bucket.Members, member.member)
			a.memberMap.Resolve(member.blockID)
		}
	}
	for _, binding := range a.bindings {
		if binding.bucketBlockID == resourceBlock.ID() {
			bucket.Bindings = append(bucket.Bindings, binding.bindings...)
			a.bindingMap.Resolve(binding.blockID)
			continue
		}
		if name != "" && name == binding.bucketID {
			bucket.Bindings = append(bucket.Bindings, binding.bindings...)
			a.bindingMap.Resolve(binding.blockID)
		}
	}

	return bucket
}
