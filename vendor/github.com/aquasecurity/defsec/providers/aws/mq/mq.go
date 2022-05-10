package mq

import "github.com/aquasecurity/defsec/parsers/types"

type MQ struct {
	types.Metadata
	Brokers []Broker
}

type Broker struct {
	types.Metadata
	PublicAccess types.BoolValue
	Logging      Logging
}

type Logging struct {
	types.Metadata
	General types.BoolValue
	Audit   types.BoolValue
}
