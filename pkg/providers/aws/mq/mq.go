package mq

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type MQ struct {
	Brokers []Broker
}

type Broker struct {
	Metadata     defsecTypes.MisconfigMetadata
	PublicAccess defsecTypes.BoolValue
	Logging      Logging
}

type Logging struct {
	Metadata defsecTypes.MisconfigMetadata
	General  defsecTypes.BoolValue
	Audit    defsecTypes.BoolValue
}
