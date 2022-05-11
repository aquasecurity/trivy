package msk

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	types.Metadata
	EncryptionInTransit EncryptionInTransit
	Logging             Logging
}

const (
	ClientBrokerEncryptionTLS            = "TLS"
	ClientBrokerEncryptionPlaintext      = "PLAINTEXT"
	ClientBrokerEncryptionTLSOrPlaintext = "TLS_PLAINTEXT"
)

type EncryptionInTransit struct {
	types.Metadata
	ClientBroker types.StringValue
}

type Logging struct {
	types.Metadata
	Broker BrokerLogging
}

type BrokerLogging struct {
	types.Metadata
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	types.Metadata
	Enabled types.BoolValue
}

type CloudwatchLogging struct {
	types.Metadata
	Enabled types.BoolValue
}

type FirehoseLogging struct {
	types.Metadata
	Enabled types.BoolValue
}
