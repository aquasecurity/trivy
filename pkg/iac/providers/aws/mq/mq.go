package mq

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type MQ struct {
	Brokers []Broker
}

type Broker struct {
	Metadata     defsecTypes.Metadata
	PublicAccess defsecTypes.BoolValue
	Logging      Logging
}

type Logging struct {
	Metadata defsecTypes.Metadata
	General  defsecTypes.BoolValue
	Audit    defsecTypes.BoolValue
}
