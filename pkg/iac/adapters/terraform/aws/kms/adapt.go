package kms

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/kms"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) kms.KMS {
	return kms.KMS{
		Keys: adaptKeys(modules),
	}
}

func adaptKeys(modules terraform.Modules) []kms.Key {
	var keys []kms.Key
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_kms_key") {
			keys = append(keys, adaptKey(resource))
		}
	}
	return keys
}

func adaptKey(resource *terraform.Block) kms.Key {
	usageAttr := resource.GetAttribute("key_usage")
	usageVal := usageAttr.AsStringValueOrDefault("ENCRYPT_DECRYPT", resource)

	enableKeyRotationAttr := resource.GetAttribute("enable_key_rotation")
	enableKeyRotationVal := enableKeyRotationAttr.AsBoolValueOrDefault(false, resource)

	return kms.Key{
		Metadata:        resource.GetMetadata(),
		Usage:           usageVal,
		RotationEnabled: enableKeyRotationVal,
	}
}
