package cloudtrail

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type CloudTrail struct {
	Trails []Trail
}

func (c CloudTrail) MultiRegionTrails() (multiRegionTrails []Trail) {
	for _, trail := range c.Trails {
		if trail.IsMultiRegion.IsTrue() {
			multiRegionTrails = append(multiRegionTrails, trail)
		}
	}
	return multiRegionTrails
}

type Trail struct {
	Metadata                  iacTypes.Metadata
	Name                      iacTypes.StringValue
	EnableLogFileValidation   iacTypes.BoolValue
	IsMultiRegion             iacTypes.BoolValue
	KMSKeyID                  iacTypes.StringValue
	CloudWatchLogsLogGroupArn iacTypes.StringValue
	IsLogging                 iacTypes.BoolValue
	BucketName                iacTypes.StringValue
	EventSelectors            []EventSelector
}

type EventSelector struct {
	Metadata      iacTypes.Metadata
	DataResources []DataResource
	ReadWriteType iacTypes.StringValue // ReadOnly, WriteOnly, All. Default value is All for TF.
}

type DataResource struct {
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue   //  You can specify only the following value: "AWS::S3::Object", "AWS::Lambda::Function" and "AWS::DynamoDB::Table".
	Values   []iacTypes.StringValue // List of ARNs/partial ARNs - e.g. arn:aws:s3:::<bucket name>/ for all objects in a bucket, arn:aws:s3:::<bucket name>/key for specific objects
}
