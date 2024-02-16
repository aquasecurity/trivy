package elb

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ELB struct {
	LoadBalancers []LoadBalancer
}

const (
	TypeApplication = "application"
	TypeGateway     = "gateway"
	TypeNetwork     = "network"
	TypeClassic     = "classic"
)

type LoadBalancer struct {
	Metadata                iacTypes.Metadata
	Type                    iacTypes.StringValue
	DropInvalidHeaderFields iacTypes.BoolValue
	Internal                iacTypes.BoolValue
	Listeners               []Listener
}

type Listener struct {
	Metadata       iacTypes.Metadata
	Protocol       iacTypes.StringValue
	TLSPolicy      iacTypes.StringValue
	DefaultActions []Action
}

type Action struct {
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue
}
