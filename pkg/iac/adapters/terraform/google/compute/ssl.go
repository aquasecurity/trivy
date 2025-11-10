package compute

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptSSLPolicies(modules terraform.Modules) (policies []compute.SSLPolicy) {
	for _, policyBlock := range modules.GetResourcesByType("google_compute_ssl_policy") {
		policy := compute.SSLPolicy{
			Metadata:          policyBlock.GetMetadata(),
			Name:              policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock),
			Profile:           policyBlock.GetAttribute("profile").AsStringValueOrDefault("", policyBlock),
			MinimumTLSVersion: policyBlock.GetAttribute("min_tls_version").AsStringValueOrDefault("TLS_1_0", policyBlock),
		}
		policies = append(policies, policy)
	}
	return policies
}
