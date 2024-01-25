package cloudtrail

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
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
	Metadata                  defsecTypes.MisconfigMetadata
	Name                      defsecTypes.StringValue
	EnableLogFileValidation   defsecTypes.BoolValue
	IsMultiRegion             defsecTypes.BoolValue
	KMSKeyID                  defsecTypes.StringValue
	CloudWatchLogsLogGroupArn defsecTypes.StringValue
	IsLogging                 defsecTypes.BoolValue
	BucketName                defsecTypes.StringValue
	EventSelectors            []EventSelector
}

type EventSelector struct {
	Metadata      defsecTypes.MisconfigMetadata
	DataResources []DataResource
	ReadWriteType defsecTypes.StringValue // ReadOnly, WriteOnly, All. Default value is All for TF.
}

type DataResource struct {
	Metadata defsecTypes.MisconfigMetadata
	Type     defsecTypes.StringValue   //  You can specify only the following value: "AWS::S3::Object", "AWS::Lambda::Function" and "AWS::DynamoDB::Table".
	Values   []defsecTypes.StringValue // List of ARNs/partial ARNs - e.g. arn:aws:s3:::<bucket name>/ for all objects in a bucket, arn:aws:s3:::<bucket name>/key for specific objects
}
