package branch_protections

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
)

func Test_AdaptDefaults(t *testing.T) {

	src := `
resource "github_branch_protection" "my-repo" {
	
}
`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	branchProtections := Adapt(modules)
	require.Len(t, branchProtections, 1)
	branchProtection := branchProtections[0]

	assert.True(t, branchProtection.RequireSignedCommits.IsFalse())
}

func Test_Adapt_RequireSignedCommitsEnabled(t *testing.T) {

	src := `
resource "github_branch_protection" "my-repo" {
	require_signed_commits = true
}
`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	branchProtections := Adapt(modules)
	require.Len(t, branchProtections, 1)
	branchProtection := branchProtections[0]

	assert.True(t, branchProtection.RequireSignedCommits.IsTrue())
	assert.Equal(t, 3, branchProtection.RequireSignedCommits.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, branchProtection.RequireSignedCommits.GetMetadata().Range().GetEndLine())
}

func Test_Adapt_RequireSignedCommitsDisabled(t *testing.T) {

	src := `
resource "github_branch_protection" "my-repo" {
	require_signed_commits = false
}
`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	branchProtections := Adapt(modules)
	require.Len(t, branchProtections, 1)
	branchProtection := branchProtections[0]

	assert.False(t, branchProtection.RequireSignedCommits.IsTrue())
	assert.Equal(t, 3, branchProtection.RequireSignedCommits.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, branchProtection.RequireSignedCommits.GetMetadata().Range().GetEndLine())
}
