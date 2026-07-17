package repositories

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/github"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected github.Repository
	}{
		{
			name: "defaults",
			src: `
resource "github_repository" "my-repo" {}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(false),
			},
		},
		{
			name: "private field",
			src: `
resource "github_repository" "my-repo" {
	private = true
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(false),
				VulnerabilityAlerts: iacTypes.BoolTest(false),
			},
		},
		{
			name: "public field",
			src: `
resource "github_repository" "my-repo" {
	private = false
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(false),
			},
		},
		{
			name: "visibility overrides private",
			src: `
resource "github_repository" "my-repo" {
	private    = true
	visibility = "public"
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(false),
			},
		},
		{
			name: "deprecated field enabled",
			src: `
resource "github_repository" "my-repo" {
	vulnerability_alerts = true
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(true),
			},
		},
		{
			name: "deprecated field disabled",
			src: `
resource "github_repository" "my-repo" {
	vulnerability_alerts = false
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(false),
			},
		},
		{
			name: "standalone resource enabled",
			src: `
resource "github_repository" "my-repo" {
	name = "my-repo"
}
resource "github_repository_vulnerability_alerts" "my-repo" {
	repository = github_repository.my-repo.name
	enabled    = true
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(true),
			},
		},
		{
			name: "standalone resource disabled",
			src: `
resource "github_repository" "my-repo" {
	name = "my-repo"
}
resource "github_repository_vulnerability_alerts" "my-repo" {
	repository = github_repository.my-repo.name
	enabled    = false
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(false),
			},
		},
		{
			name: "standalone resource default enabled",
			src: `
resource "github_repository" "my-repo" {
	name = "my-repo"
}
resource "github_repository_vulnerability_alerts" "my-repo" {
	repository = github_repository.my-repo.name
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(true),
			},
		},
		{
			name: "disabled standalone resource overrides enabled deprecated field",
			src: `
resource "github_repository" "my-repo" {
	name                 = "my-repo"
	vulnerability_alerts = false
}
resource "github_repository_vulnerability_alerts" "my-repo" {
	repository = github_repository.my-repo.name
	enabled    = true
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(true),
			},
		},
		{
			name: "enabled standalone resource overrides disabled deprecated field",
			src: `
resource "github_repository" "my-repo" {
	name                 = "my-repo"
	vulnerability_alerts = true
}
resource "github_repository_vulnerability_alerts" "my-repo" {
	repository = github_repository.my-repo.name
	enabled    = false
}
`,
			expected: github.Repository{
				Public:              iacTypes.BoolTest(true),
				VulnerabilityAlerts: iacTypes.BoolTest(false),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, tt.src, ".tf")
			adapted := Adapt(modules)
			require.Len(t, adapted, 1)
			testutil.AssertDefsecEqual(t, tt.expected, adapted[0])
		})
	}
}
