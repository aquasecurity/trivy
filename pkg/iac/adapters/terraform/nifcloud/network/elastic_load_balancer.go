package network

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/network"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptElasticLoadBalancers(modules terraform.Modules) []network.ElasticLoadBalancer {
	var elasticLoadBalancers []network.ElasticLoadBalancer

	for _, resource := range modules.GetResourcesByType("nifcloud_elb") {
		elasticLoadBalancers = append(elasticLoadBalancers, adaptElasticLoadBalancer(resource, modules))
	}
	return elasticLoadBalancers
}

func adaptElasticLoadBalancer(resource *terraform.Block, modules terraform.Modules) network.ElasticLoadBalancer {
	var listeners []network.ElasticLoadBalancerListener
	var networkInterfaces []network.NetworkInterface

	networkInterfaceBlocks := resource.GetBlocks("network_interface")
	for _, networkInterfaceBlock := range networkInterfaceBlocks {
		networkInterfaces = append(
			networkInterfaces,
			network.NetworkInterface{
				Metadata:     networkInterfaceBlock.GetMetadata(),
				NetworkID:    networkInterfaceBlock.GetAttribute("network_id").AsStringValueOrDefault("", resource),
				IsVipNetwork: networkInterfaceBlock.GetAttribute("is_vip_network").AsBoolValueOrDefault(true, resource),
			},
		)
	}

	listeners = append(listeners, adaptElasticLoadBalancerListener(resource))
	for _, listenerBlock := range modules.GetReferencingResources(resource, "nifcloud_elb_listener", "elb_id") {
		listeners = append(listeners, adaptElasticLoadBalancerListener(listenerBlock))
	}

	return network.ElasticLoadBalancer{
		Metadata:          resource.GetMetadata(),
		NetworkInterfaces: networkInterfaces,
		Listeners:         listeners,
	}
}

func adaptElasticLoadBalancerListener(resource *terraform.Block) network.ElasticLoadBalancerListener {
	return network.ElasticLoadBalancerListener{
		Metadata: resource.GetMetadata(),
		Protocol: resource.GetAttribute("protocol").AsStringValueOrDefault("", resource),
	}
}
