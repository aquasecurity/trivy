package resolvers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveSubdirFromSource(t *testing.T) {

	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:     "address with scheme and query string",
			source:   "git::https://github.com/aquasecurity/terraform-modules.git//modules/ecs-service?ref=v0.1.0",
			expected: "git::https://github.com/aquasecurity/terraform-modules.git?ref=v0.1.0",
		},
		{
			name:     "address with scheme",
			source:   "git::https://github.com/aquasecurity/terraform-modules.git//modules/ecs-service",
			expected: "git::https://github.com/aquasecurity/terraform-modules.git",
		},
		{
			name:     "registry address",
			source:   "hashicorp/consul/aws//modules/consul-cluster",
			expected: "hashicorp/consul/aws",
		},
		{
			name:     "without subdir",
			source:   `hashicorp/consul/aws`,
			expected: `hashicorp/consul/aws`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := removeSubdirFromSource(test.source)
			assert.Equal(t, test.expected, got)
		})
	}
}
