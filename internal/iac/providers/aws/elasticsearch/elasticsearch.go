package elasticsearch

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Elasticsearch struct {
	Domains []Domain
}

type Domain struct {
	Metadata               iacTypes.Metadata
	DomainName             iacTypes.StringValue
	AccessPolicies         iacTypes.StringValue
	DedicatedMasterEnabled iacTypes.BoolValue
	VpcId                  iacTypes.StringValue
	LogPublishing          LogPublishing
	TransitEncryption      TransitEncryption
	AtRestEncryption       AtRestEncryption
	ServiceSoftwareOptions ServiceSoftwareOptions
	Endpoint               Endpoint
}

type ServiceSoftwareOptions struct {
	Metadata        iacTypes.Metadata
	CurrentVersion  iacTypes.StringValue
	NewVersion      iacTypes.StringValue
	UpdateAvailable iacTypes.BoolValue
	UpdateStatus    iacTypes.StringValue
}

type Endpoint struct {
	Metadata     iacTypes.Metadata
	EnforceHTTPS iacTypes.BoolValue
	TLSPolicy    iacTypes.StringValue
}

type LogPublishing struct {
	Metadata              iacTypes.Metadata
	AuditEnabled          iacTypes.BoolValue
	CloudWatchLogGroupArn iacTypes.StringValue
}

type TransitEncryption struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type AtRestEncryption struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	KmsKeyId iacTypes.StringValue
}
