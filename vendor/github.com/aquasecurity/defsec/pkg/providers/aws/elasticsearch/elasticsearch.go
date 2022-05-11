package elasticsearch

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Elasticsearch struct {
	Domains []Domain
}

type Domain struct {
	types.Metadata
	DomainName        types.StringValue
	LogPublishing     LogPublishing
	TransitEncryption TransitEncryption
	AtRestEncryption  AtRestEncryption
	Endpoint          Endpoint
}

type Endpoint struct {
	types.Metadata
	EnforceHTTPS types.BoolValue
	TLSPolicy    types.StringValue
}

type LogPublishing struct {
	types.Metadata
	AuditEnabled types.BoolValue
}

type TransitEncryption struct {
	types.Metadata
	Enabled types.BoolValue
}

type AtRestEncryption struct {
	types.Metadata
	Enabled types.BoolValue
}
