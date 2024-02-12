package elasticsearch

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Elasticsearch struct {
	Domains []Domain
}

type Domain struct {
	Metadata               defsecTypes.Metadata
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
	Metadata        defsecTypes.Metadata
	CurrentVersion  defsecTypes.StringValue
	NewVersion      defsecTypes.StringValue
	UpdateAvailable defsecTypes.BoolValue
	UpdateStatus    defsecTypes.StringValue
}

type Endpoint struct {
	Metadata     defsecTypes.Metadata
	EnforceHTTPS defsecTypes.BoolValue
	TLSPolicy    defsecTypes.StringValue
}

type LogPublishing struct {
	Metadata              defsecTypes.Metadata
	AuditEnabled          defsecTypes.BoolValue
	CloudWatchLogGroupArn defsecTypes.StringValue
}

type TransitEncryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type AtRestEncryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KmsKeyId defsecTypes.StringValue
}
