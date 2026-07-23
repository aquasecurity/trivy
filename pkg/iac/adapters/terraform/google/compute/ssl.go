package compute

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptSSLPolicies(modules terraform.Modules) (policies []compute.SSLPolicy) {
	for _, policyBlock := range modules.GetResourcesByType("google_compute_ssl_policy") {
		policy := compute.SSLPolicy{
			Metadata:          policyBlock.GetMetadata(),
			Name:              policyBlock.GetAttribute("name").AsStringValue(),
			Profile:           policyBlock.GetAttribute("profile").AsStringValue(),
			MinimumTLSVersion: policyBlock.GetAttribute("min_tls_version").AsStringValue("TLS_1_0"),
		}
		policies = append(policies, policy)
	}
	return policies
}
