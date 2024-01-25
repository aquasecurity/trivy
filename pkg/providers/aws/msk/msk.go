package msk

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata            defsecTypes.MisconfigMetadata
	EncryptionInTransit EncryptionInTransit
	EncryptionAtRest    EncryptionAtRest
	Logging             Logging
}

const (
	ClientBrokerEncryptionTLS            = "TLS"
	ClientBrokerEncryptionPlaintext      = "PLAINTEXT"
	ClientBrokerEncryptionTLSOrPlaintext = "TLS_PLAINTEXT"
)

type EncryptionInTransit struct {
	Metadata     defsecTypes.MisconfigMetadata
	ClientBroker defsecTypes.StringValue
}

type EncryptionAtRest struct {
	Metadata  defsecTypes.MisconfigMetadata
	KMSKeyARN defsecTypes.StringValue
	Enabled   defsecTypes.BoolValue
}

type Logging struct {
	Metadata defsecTypes.MisconfigMetadata
	Broker   BrokerLogging
}

type BrokerLogging struct {
	Metadata   defsecTypes.MisconfigMetadata
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

type CloudwatchLogging struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

type FirehoseLogging struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}
