package kubernetes

import (
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/kubernetes"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

var versionRegex = regexp.MustCompile(`^v\d+(beta\d+)?$`)

func Adapt(modules terraform.Modules) kubernetes.Kubernetes {
	return kubernetes.Kubernetes{
		NetworkPolicies: adaptNetworkPolicies(modules),
	}
}

func adaptNetworkPolicies(modules terraform.Modules) []kubernetes.NetworkPolicy {
	var networkPolicies []kubernetes.NetworkPolicy
	for _, module := range modules {
		for _, resource := range getBlocksIgnoreVersion(module, "resource", "kubernetes_network_policy") {
			networkPolicies = append(networkPolicies, adaptNetworkPolicy(resource))
		}
	}
	return networkPolicies
}

func adaptNetworkPolicy(resourceBlock *terraform.Block) kubernetes.NetworkPolicy {

	policy := kubernetes.NetworkPolicy{
		Metadata: resourceBlock.GetMetadata(),
		Spec: kubernetes.NetworkPolicySpec{
			Metadata: resourceBlock.GetMetadata(),
			Egress: kubernetes.Egress{
				Metadata:         resourceBlock.GetMetadata(),
				Ports:            nil,
				DestinationCIDRs: nil,
			},
			Ingress: kubernetes.Ingress{
				Metadata:    resourceBlock.GetMetadata(),
				Ports:       nil,
				SourceCIDRs: nil,
			},
		},
	}

	if specBlock := resourceBlock.GetBlock("spec"); specBlock.IsNotNil() {
		if egressBlock := specBlock.GetBlock("egress"); egressBlock.IsNotNil() {
			policy.Spec.Egress.Metadata = egressBlock.GetMetadata()
			for _, port := range egressBlock.GetBlocks("ports") {
				numberAttr := port.GetAttribute("number")
				numberVal := numberAttr.AsStringValueOrDefault("", port)

				protocolAttr := port.GetAttribute("protocol")
				protocolVal := protocolAttr.AsStringValueOrDefault("", port)

				policy.Spec.Egress.Ports = append(policy.Spec.Egress.Ports, kubernetes.Port{
					Metadata: port.GetMetadata(),
					Number:   numberVal,
					Protocol: protocolVal,
				})
			}

			for _, to := range egressBlock.GetBlocks("to") {
				cidrAtrr := to.GetBlock("ip_block").GetAttribute("cidr")
				cidrVal := cidrAtrr.AsStringValueOrDefault("", to)

				policy.Spec.Egress.DestinationCIDRs = append(policy.Spec.Egress.DestinationCIDRs, cidrVal)
			}
		}

		if ingressBlock := specBlock.GetBlock("ingress"); ingressBlock.IsNotNil() {
			policy.Spec.Ingress.Metadata = ingressBlock.GetMetadata()
			for _, port := range ingressBlock.GetBlocks("ports") {
				numberAttr := port.GetAttribute("number")
				numberVal := numberAttr.AsStringValueOrDefault("", port)

				protocolAttr := port.GetAttribute("protocol")
				protocolVal := protocolAttr.AsStringValueOrDefault("", port)

				policy.Spec.Ingress.Ports = append(policy.Spec.Ingress.Ports, kubernetes.Port{
					Metadata: port.GetMetadata(),
					Number:   numberVal,
					Protocol: protocolVal,
				})
			}

			for _, from := range ingressBlock.GetBlocks("from") {
				cidrAtrr := from.GetBlock("ip_block").GetAttribute("cidr")
				cidrVal := cidrAtrr.AsStringValueOrDefault("", from)

				policy.Spec.Ingress.SourceCIDRs = append(policy.Spec.Ingress.SourceCIDRs, cidrVal)
			}
		}
	}

	return policy
}

// https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/guides/versioned-resources
func getBlocksIgnoreVersion(module *terraform.Module, blockType, resourceType string) terraform.Blocks {
	var res terraform.Blocks
	for _, block := range module.GetBlocks().OfType(blockType) {
		if isMatchingTypeLabel(block.TypeLabel(), resourceType) {
			res = append(res, block)
		}
	}
	return res
}

func isMatchingTypeLabel(typeLabel, resourceType string) bool {
	if typeLabel == resourceType {
		return true
	}

	versionPart, found := strings.CutPrefix(typeLabel, resourceType+"_")
	if !found {
		return false
	}

	return versionRegex.MatchString(versionPart)
}
