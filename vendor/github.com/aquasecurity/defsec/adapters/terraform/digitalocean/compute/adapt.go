package compute

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/digitalocean/compute"
)

func Adapt(modules terraform.Modules) compute.Compute {
	return compute.Compute{
		Droplets:           adaptDroplets(modules),
		Firewalls:          adaptFirewalls(modules),
		LoadBalancers:      adaptLoadBalancers(modules),
		KubernetesClusters: adaptKubernetesClusters(modules),
	}
}

func adaptDroplets(module terraform.Modules) []compute.Droplet {
	var droplets []compute.Droplet

	for _, module := range module {
		for _, block := range module.GetResourcesByType("digitalocean_droplet") {
			droplet := compute.Droplet{
				Metadata: block.GetMetadata(),
			}
			sshKeys := block.GetAttribute("ssh_keys")
			if sshKeys != nil {
				droplet.SSHKeys = []types.StringValue{}
				for _, value := range sshKeys.ValueAsStrings() {
					droplet.SSHKeys = append(droplet.SSHKeys, types.String(value, sshKeys.GetMetadata()))
				}
			}

			droplets = append(droplets, droplet)
		}
	}
	return droplets
}

func adaptFirewalls(module terraform.Modules) []compute.Firewall {
	var firewalls []compute.Firewall

	for _, block := range module.GetResourcesByType("digitalocean_firewall") {
		inboundRules := block.GetBlocks("inbound_rule")
		outboundRules := block.GetBlocks("outbound_rule")

		inboundFirewallRules := []compute.InboundFirewallRule{}
		for _, inBoundRule := range inboundRules {
			inboundFirewallRule := compute.InboundFirewallRule{}
			if ibSourceAddresses := inBoundRule.GetAttribute("source_addresses"); ibSourceAddresses != nil {
				inboundFirewallRule.SourceAddresses = []types.StringValue{}
				for _, value := range ibSourceAddresses.ValueAsStrings() {
					inboundFirewallRule.SourceAddresses = append(inboundFirewallRule.SourceAddresses, types.String(value, inBoundRule.GetMetadata()))
				}
			}
			inboundFirewallRules = append(inboundFirewallRules, inboundFirewallRule)
		}

		outboundFirewallRules := []compute.OutboundFirewallRule{}
		for _, outBoundRule := range outboundRules {
			outboundFirewallRule := compute.OutboundFirewallRule{}
			if obDestinationAddresses := outBoundRule.GetAttribute("destination_addresses"); obDestinationAddresses != nil {
				outboundFirewallRule.DestinationAddresses = []types.StringValue{}
				for _, value := range obDestinationAddresses.ValueAsStrings() {
					outboundFirewallRule.DestinationAddresses = append(outboundFirewallRule.DestinationAddresses, types.String(value, outBoundRule.GetMetadata()))
				}
			}
			outboundFirewallRules = append(outboundFirewallRules, outboundFirewallRule)
		}
		firewalls = append(firewalls, compute.Firewall{
			Metadata:      block.GetMetadata(),
			InboundRules:  inboundFirewallRules,
			OutboundRules: outboundFirewallRules,
		})
	}

	return firewalls
}

func adaptLoadBalancers(module terraform.Modules) (loadBalancers []compute.LoadBalancer) {

	for _, block := range module.GetResourcesByType("digitalocean_loadbalancer") {
		forwardingRules := block.GetBlocks("forwarding_rule")
		fRules := []compute.ForwardingRule{}

		for _, fRule := range forwardingRules {
			rule := compute.ForwardingRule{}
			rule.Metadata = fRule.GetMetadata()
			rule.EntryProtocol = fRule.GetAttribute("entry_protocol").AsStringValueOrDefault("", fRule)
			fRules = append(fRules, rule)
		}
		loadBalancers = append(loadBalancers, compute.LoadBalancer{
			Metadata:        block.GetMetadata(),
			ForwardingRules: fRules,
		})
	}

	return loadBalancers
}

func adaptKubernetesClusters(module terraform.Modules) (kubernetesClusters []compute.KubernetesCluster) {
	for _, block := range module.GetResourcesByType("digitalocean_kubernetes_cluster") {
		kubernetesClusters = append(kubernetesClusters, compute.KubernetesCluster{
			Metadata:     block.GetMetadata(),
			AutoUpgrade:  block.GetAttribute("auto_upgrade").AsBoolValueOrDefault(false, block),
			SurgeUpgrade: block.GetAttribute("surge_upgrade").AsBoolValueOrDefault(false, block),
		})
	}
	return kubernetesClusters
}
