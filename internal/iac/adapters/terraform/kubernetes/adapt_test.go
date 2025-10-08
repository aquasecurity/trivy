package kubernetes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsMatchingTypeLabel(t *testing.T) {
	tests := []struct {
		name         string
		typeLabel    string
		resourceType string
		expected     bool
	}{
		{
			name:         "without version",
			typeLabel:    "kubernetes_network_policy",
			resourceType: "kubernetes_network_policy",
			expected:     true,
		},
		{
			name:         "v1",
			typeLabel:    "kubernetes_network_policy_v1",
			resourceType: "kubernetes_network_policy",
			expected:     true,
		},
		{
			name:         "beta version",
			typeLabel:    "kubernetes_horizontal_pod_autoscaler_v2beta2",
			resourceType: "kubernetes_horizontal_pod_autoscaler",
			expected:     true,
		},
		{
			name:         "another type of resource",
			typeLabel:    "kubernetes_network_policy",
			resourceType: "kubernetes_horizontal_pod_autoscaler",
			expected:     false,
		},
		{
			name:         "similar resource type",
			typeLabel:    "kubernetes_network_policy_test_v1",
			resourceType: "kubernetes_network_policy",
			expected:     false,
		},
		{
			name:         "empty resource type",
			typeLabel:    "kubernetes_network_policy_test_v1",
			resourceType: "",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMatchingTypeLabel(tt.typeLabel, tt.resourceType)
			assert.Equal(t, tt.expected, got)
		})
	}
}
