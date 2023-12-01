package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_adaptProjectMetadata(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  compute.ProjectMetadata
	}{
		{
			name: "defined",
			terraform: `
			resource "google_compute_project_metadata" "example" {
				metadata = {
				  enable-oslogin = true
				}
			  }
`,
			expected: compute.ProjectMetadata{
				Metadata:      defsecTypes.NewTestMetadata(),
				EnableOSLogin: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_project_metadata" "example" {
				metadata = {
				}
			  }
`,
			expected: compute.ProjectMetadata{
				Metadata:      defsecTypes.NewTestMetadata(),
				EnableOSLogin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptProjectMetadata(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
