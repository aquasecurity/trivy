package elasticsearch

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Elasticsearch struct {
	Domains []Domain
}

type Domain struct {
	Metadata               defsecTypes.MisconfigMetadata
	DomainName             defsecTypes.StringValue
	AccessPolicies         defsecTypes.StringValue
	DedicatedMasterEnabled defsecTypes.BoolValue
	VpcId                  defsecTypes.StringValue
	LogPublishing          LogPublishing
	TransitEncryption      TransitEncryption
	AtRestEncryption       AtRestEncryption
	ServiceSoftwareOptions ServiceSoftwareOptions
	Endpoint               Endpoint
}

type ServiceSoftwareOptions struct {
	Metadata        defsecTypes.MisconfigMetadata
	CurrentVersion  defsecTypes.StringValue
	NewVersion      defsecTypes.StringValue
	UpdateAvailable defsecTypes.BoolValue
	UpdateStatus    defsecTypes.StringValue
}

type Endpoint struct {
	Metadata     defsecTypes.MisconfigMetadata
	EnforceHTTPS defsecTypes.BoolValue
	TLSPolicy    defsecTypes.StringValue
}

type LogPublishing struct {
	Metadata              defsecTypes.MisconfigMetadata
	AuditEnabled          defsecTypes.BoolValue
	CloudWatchLogGroupArn defsecTypes.StringValue
}

type TransitEncryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

type AtRestEncryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
	KmsKeyId defsecTypes.StringValue
}
