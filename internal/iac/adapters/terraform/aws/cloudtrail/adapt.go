package cloudtrail

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
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

	var selectors []cloudtrail.EventSelector
	for _, selBlock := range resource.GetBlocks("event_selector") {
		var resources []cloudtrail.DataResource
		for _, resBlock := range selBlock.GetBlocks("data_resource") {
			resources = append(resources, cloudtrail.DataResource{
				Metadata: resBlock.GetMetadata(),
				Type:     resBlock.GetAttribute("type").AsStringValueOrDefault("", resBlock),
				Values:   resBlock.GetAttribute("values").AsStringValues(),
			})
		}
		selector := cloudtrail.EventSelector{
			Metadata:      selBlock.GetMetadata(),
			DataResources: resources,
			ReadWriteType: selBlock.GetAttribute("read_write_type").AsStringValueOrDefault("All", selBlock),
		}
		selectors = append(selectors, selector)
	}

	return cloudtrail.Trail{
		Metadata:                  resource.GetMetadata(),
		Name:                      nameVal,
		EnableLogFileValidation:   enableLogFileValidationVal,
		IsMultiRegion:             isMultiRegionVal,
		KMSKeyID:                  KMSKeyIDVal,
		CloudWatchLogsLogGroupArn: resource.GetAttribute("cloud_watch_logs_group_arn").AsStringValueOrDefault("", resource),
		IsLogging:                 resource.GetAttribute("enable_logging").AsBoolValueOrDefault(true, resource),
		BucketName:                resource.GetAttribute("s3_bucket_name").AsStringValueOrDefault("", resource),
		EventSelectors:            selectors,
	}
}
