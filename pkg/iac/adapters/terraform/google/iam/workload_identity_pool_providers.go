package iam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
)

// See https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/iam_workload_identity_pool_provider

func (a *adapter) adaptWorkloadIdentityPoolProviders() {
	for _, resource := range a.modules.GetResourcesByType("google_iam_workload_identity_pool_provider") {
		a.workloadIdentityPoolProviders = append(a.workloadIdentityPoolProviders, iam.WorkloadIdentityPoolProvider{
			Metadata:                       resource.GetMetadata(),
			WorkloadIdentityPoolId:         resource.GetAttribute("workload_identity_pool_id").AsStringValueOrDefault("", resource),
			WorkloadIdentityPoolProviderId: resource.GetAttribute("workload_identity_pool_provider_id").AsStringValueOrDefault("", resource),
			AttributeCondition:             resource.GetAttribute("attribute_condition").AsStringValueOrDefault("", resource),
		})
	}
}
