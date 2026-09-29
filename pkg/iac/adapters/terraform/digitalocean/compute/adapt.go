package compute

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean/compute"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
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
				SSHKeys:  nil,
			}
			sshKeys := block.GetAttribute("ssh_keys")
			if sshKeys != nil {
				droplet.SSHKeys = sshKeys.AsStringValues()
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

		var inboundFirewallRules []compute.InboundFirewallRule
		for _, inBoundRule := range inboundRules {
			inboundFirewallRule := compute.InboundFirewallRule{
				Metadata: inBoundRule.GetMetadata(),
			}
			if ibSourceAddresses := inBoundRule.GetAttribute("source_addresses"); ibSourceAddresses != nil {
				inboundFirewallRule.SourceAddresses = ibSourceAddresses.AsStringValues()
			}
			inboundFirewallRules = append(inboundFirewallRules, inboundFirewallRule)
		}

		var outboundFirewallRules []compute.OutboundFirewallRule
		for _, outBoundRule := range outboundRules {
			outboundFirewallRule := compute.OutboundFirewallRule{
				Metadata: outBoundRule.GetMetadata(),
			}
			if obDestinationAddresses := outBoundRule.GetAttribute("destination_addresses"); obDestinationAddresses != nil {
				outboundFirewallRule.DestinationAddresses = obDestinationAddresses.AsStringValues()
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
		var fRules []compute.ForwardingRule

		for _, fRule := range forwardingRules {
			rule := compute.ForwardingRule{
				Metadata:      fRule.GetMetadata(),
				EntryProtocol: fRule.GetAttribute("entry_protocol").AsStringValueOrDefault("", fRule),
			}
			fRules = append(fRules, rule)
		}
		loadBalancers = append(loadBalancers, compute.LoadBalancer{
			Metadata:            block.GetMetadata(),
			RedirectHttpToHttps: block.GetAttribute("redirect_http_to_https").AsBoolValueOrDefault(false, block),
			ForwardingRules:     fRules,
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
