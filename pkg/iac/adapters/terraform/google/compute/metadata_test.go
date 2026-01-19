package compute

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
				EnableOSLogin: iacTypes.BoolTest(true),
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
			expected: compute.ProjectMetadata{},
		},
		{
			name: "handles metadata values in various formats",
			terraform: `resource "google_compute_project_metadata" "example" {
	metadata = {
		enable-oslogin = "TRUE"
		block-project-ssh-keys = 1
		serial-port-enable = "yes"
	}
}
`,
			expected: compute.ProjectMetadata{
				EnableOSLogin: iacTypes.BoolTest(true),
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
