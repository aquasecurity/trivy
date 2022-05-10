package elb

import (
	"github.com/aquasecurity/defsec/internal/types"
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
	types.Metadata
	Type                    types.StringValue
	DropInvalidHeaderFields types.BoolValue
	Internal                types.BoolValue
	Listeners               []Listener
}

type Listener struct {
	types.Metadata
	Protocol      types.StringValue
	TLSPolicy     types.StringValue
	DefaultAction Action
}

type Action struct {
	types.Metadata
	Type types.StringValue
}
