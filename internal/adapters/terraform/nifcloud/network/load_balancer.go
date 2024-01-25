package network

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/network"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func adaptLoadBalancers(modules terraform.Modules) []network.LoadBalancer {
	var loadBalancers []network.LoadBalancer

	for _, resource := range modules.GetResourcesByType("nifcloud_load_balancer") {
		loadBalancers = append(loadBalancers, adaptLoadBalancer(resource, modules))
	}

	return loadBalancers
}

func adaptLoadBalancer(resource *terraform.Block, modules terraform.Modules) network.LoadBalancer {
	var listeners []network.LoadBalancerListener

	listeners = append(listeners, adaptListener(resource))
	for _, listenerBlock := range modules.GetReferencingResources(resource, "nifcloud_load_balancer_listener", "load_balancer_name") {
		listeners = append(listeners, adaptListener(listenerBlock))
	}

	return network.LoadBalancer{
		Metadata:  resource.GetMetadata(),
		Listeners: listeners,
	}
}

func adaptListener(resource *terraform.Block) network.LoadBalancerListener {
	protocolVal := defsecTypes.String("", resource.GetMetadata())
	policyVal := defsecTypes.String("", resource.GetMetadata())

	portAttr := resource.GetAttribute("load_balancer_port")
	if portAttr.IsNotNil() && portAttr.IsNumber() {
		port := portAttr.AsNumber()
		switch port {
		case 21:
			protocolVal = defsecTypes.String("FTP", portAttr.GetMetadata())
		case 80:
			protocolVal = defsecTypes.String("HTTP", portAttr.GetMetadata())
		case 443:
			protocolVal = defsecTypes.String("HTTPS", portAttr.GetMetadata())
		default:
			protocolVal = defsecTypes.String("custom", portAttr.GetMetadata())
		}
	}

	policyIDAttr := resource.GetAttribute("ssl_policy_id")
	if policyIDAttr.IsNotNil() && policyIDAttr.IsString() {
		policyVal = policyIDAttr.AsStringValueOrDefault("", resource)
	}

	policyNameAttr := resource.GetAttribute("ssl_policy_name")
	if policyNameAttr.IsNotNil() && policyNameAttr.IsString() {
		policyVal = policyNameAttr.AsStringValueOrDefault("", resource)
	}

	return network.LoadBalancerListener{
		Metadata:  resource.GetMetadata(),
		Protocol:  protocolVal,
		TLSPolicy: policyVal,
	}
}
