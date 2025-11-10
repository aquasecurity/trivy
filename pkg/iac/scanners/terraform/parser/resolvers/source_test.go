package resolvers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitPackageSubdirRaw(t *testing.T) {

	tests := []struct {
		name           string
		source         string
		expectedPkg    string
		expectedSubdir string
	}{
		{
			name:           "address with scheme and query string",
			source:         "git::https://github.com/aquasecurity/terraform-modules.git//modules/ecs-service?ref=v0.1.0",
			expectedPkg:    "git::https://github.com/aquasecurity/terraform-modules.git?ref=v0.1.0",
			expectedSubdir: "modules/ecs-service",
		},
		{
			name:           "address with scheme",
			source:         "git::https://github.com/aquasecurity/terraform-modules.git//modules/ecs-service",
			expectedPkg:    "git::https://github.com/aquasecurity/terraform-modules.git",
			expectedSubdir: "modules/ecs-service",
		},
		{
			name:           "registry address",
			source:         "hashicorp/consul/aws//modules/consul-cluster",
			expectedPkg:    "hashicorp/consul/aws",
			expectedSubdir: "modules/consul-cluster",
		},
		{
			name:           "without subdir",
			source:         `hashicorp/consul/aws`,
			expectedPkg:    `hashicorp/consul/aws`,
			expectedSubdir: ".",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgAddr, subdir := splitPackageSubdirRaw(test.source)
			assert.Equal(t, test.expectedPkg, pkgAddr)
			assert.Equal(t, test.expectedSubdir, subdir)
		})
	}
}
