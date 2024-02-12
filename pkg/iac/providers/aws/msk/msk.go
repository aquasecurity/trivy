package msk

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata            defsecTypes.Metadata
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
	Metadata     defsecTypes.Metadata
	ClientBroker defsecTypes.StringValue
}

type EncryptionAtRest struct {
	Metadata  defsecTypes.Metadata
	KMSKeyARN defsecTypes.StringValue
	Enabled   defsecTypes.BoolValue
}

type Logging struct {
	Metadata defsecTypes.Metadata
	Broker   BrokerLogging
}

type BrokerLogging struct {
	Metadata   defsecTypes.Metadata
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type CloudwatchLogging struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type FirehoseLogging struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}
