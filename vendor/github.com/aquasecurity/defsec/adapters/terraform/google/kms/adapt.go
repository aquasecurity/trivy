package kms

import (
	"strconv"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/parsers/terraform"

	"github.com/aquasecurity/defsec/providers/google/kms"
)

func Adapt(modules terraform.Modules) kms.KMS {
	return kms.KMS{
		KeyRings: adaptKeyRings(modules),
	}
}

func adaptKeyRings(modules terraform.Modules) []kms.KeyRing {
	var keyRings []kms.KeyRing
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_kms_key_ring") {
			var keys []kms.Key

			keyBlocks := module.GetReferencingResources(resource, "google_kms_crypto_key", "key_ring")
			for _, keyBlock := range keyBlocks {
				keys = append(keys, adaptKey(keyBlock))
			}
			keyRings = append(keyRings, kms.KeyRing{
				Metadata: resource.GetMetadata(),
				Keys:     keys,
			})
		}
	}
	return keyRings
}

func adaptKey(resource *terraform.Block) kms.Key {

	key := kms.Key{
		Metadata:              resource.GetMetadata(),
		RotationPeriodSeconds: types.IntDefault(-1, resource.GetMetadata()),
	}

	rotationPeriodAttr := resource.GetAttribute("rotation_period")
	if !rotationPeriodAttr.IsString() {
		return key
	}
	rotationStr := rotationPeriodAttr.Value().AsString()
	if rotationStr[len(rotationStr)-1:] != "s" {
		return key
	}
	seconds, err := strconv.Atoi(rotationStr[:len(rotationStr)-1])
	if err != nil {
		return key
	}

	key.RotationPeriodSeconds = types.Int(seconds, rotationPeriodAttr.GetMetadata())
	return key
}
