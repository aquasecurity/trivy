package compute

import "github.com/aquasecurity/defsec/parsers/types"

type Compute struct {
	types.Metadata
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	types.Metadata
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	types.Metadata
	SurgeUpgrade types.BoolValue
	AutoUpgrade  types.BoolValue
}

type LoadBalancer struct {
	types.Metadata
	ForwardingRules []ForwardingRule
}

type ForwardingRule struct {
	types.Metadata
	EntryProtocol types.StringValue
}

type OutboundFirewallRule struct {
	types.Metadata
	DestinationAddresses []types.StringValue
}

type InboundFirewallRule struct {
	types.Metadata
	SourceAddresses []types.StringValue
}

type Droplet struct {
	types.Metadata
	SSHKeys []types.StringValue
}
