package compute

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Compute struct {
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	Metadata      iacTypes.Metadata
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	Metadata     iacTypes.Metadata
	SurgeUpgrade iacTypes.BoolValue
	AutoUpgrade  iacTypes.BoolValue
}

type LoadBalancer struct {
	Metadata            iacTypes.Metadata
	ForwardingRules     []ForwardingRule
	RedirectHttpToHttps iacTypes.BoolValue
}

type ForwardingRule struct {
	Metadata      iacTypes.Metadata
	EntryProtocol iacTypes.StringValue
}

type OutboundFirewallRule struct {
	Metadata             iacTypes.Metadata
	DestinationAddresses []iacTypes.StringValue
}

type InboundFirewallRule struct {
	Metadata        iacTypes.Metadata
	SourceAddresses []iacTypes.StringValue
}

type Droplet struct {
	Metadata iacTypes.Metadata
	SSHKeys  []iacTypes.StringValue
}
