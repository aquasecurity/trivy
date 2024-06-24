package repositories

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
)

func Test_AdaptDefaults(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	
}
`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.True(t, repo.Public.IsTrue())
}

func Test_Adapt_Private(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	private = true
}
`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.False(t, repo.Public.IsTrue())
	assert.Equal(t, 3, repo.Public.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, repo.Public.GetMetadata().Range().GetEndLine())
}

func Test_Adapt_Public(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	private = false
}
`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.True(t, repo.Public.IsTrue())
	assert.Equal(t, 3, repo.Public.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, repo.Public.GetMetadata().Range().GetEndLine())
}

func Test_Adapt_VisibilityOverride(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	private = true
	visibility = "public"
}
`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.True(t, repo.Public.IsTrue())
	assert.Equal(t, 4, repo.Public.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, repo.Public.GetMetadata().Range().GetEndLine())
}

func Test_Adapt_VulnerabilityAlertsEnabled(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	vulnerability_alerts = true
}
`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.True(t, repo.VulnerabilityAlerts.IsTrue())
	assert.Equal(t, 3, repo.VulnerabilityAlerts.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, repo.VulnerabilityAlerts.GetMetadata().Range().GetEndLine())
}

func Test_Adapt_VulnerabilityAlertsDisabled(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	vulnerability_alerts = false
}
`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.False(t, repo.VulnerabilityAlerts.IsTrue())
	assert.Equal(t, 3, repo.VulnerabilityAlerts.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, repo.VulnerabilityAlerts.GetMetadata().Range().GetEndLine())
}
