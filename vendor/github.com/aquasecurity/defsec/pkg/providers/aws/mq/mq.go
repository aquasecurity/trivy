package mq

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type MQ struct {
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
