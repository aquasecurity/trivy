package cloudtrail

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) cloudtrail.CloudTrail {
	return cloudtrail.CloudTrail{
		Trails: adaptTrails(modules),
	}
}

func adaptTrails(modules terraform.Modules) []cloudtrail.Trail {
	var trails []cloudtrail.Trail

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudtrail") {
			trails = append(trails, adaptTrail(resource))
		}
	}
	return trails
}

func adaptTrail(resource *terraform.Block) cloudtrail.Trail {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	enableLogFileValidationAttr := resource.GetAttribute("enable_log_file_validation")
	enableLogFileValidationVal := enableLogFileValidationAttr.AsBoolValueOrDefault(false, resource)

	isMultiRegionAttr := resource.GetAttribute("is_multi_region_trail")
	isMultiRegionVal := isMultiRegionAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	return cloudtrail.Trail{
		Metadata:                resource.GetMetadata(),
		Name:                    nameVal,
		EnableLogFileValidation: enableLogFileValidationVal,
		IsMultiRegion:           isMultiRegionVal,
		KMSKeyID:                KMSKeyIDVal,
	}
}
