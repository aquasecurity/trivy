package msk

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata            iacTypes.Metadata
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
	Metadata     iacTypes.Metadata
	ClientBroker iacTypes.StringValue
}

type EncryptionAtRest struct {
	Metadata  iacTypes.Metadata
	KMSKeyARN iacTypes.StringValue
	Enabled   iacTypes.BoolValue
}

type Logging struct {
	Metadata iacTypes.Metadata
	Broker   BrokerLogging
}

type BrokerLogging struct {
	Metadata   iacTypes.Metadata
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type CloudwatchLogging struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type FirehoseLogging struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}
