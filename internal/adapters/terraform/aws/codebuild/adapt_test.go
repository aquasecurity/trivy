package codebuild

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/codebuild"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptProject(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  codebuild.Project
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_codebuild_project" "codebuild" {

				artifacts {
					encryption_disabled = false
				}

				secondary_artifacts {
					encryption_disabled = false
				}
				secondary_artifacts {
					encryption_disabled = true
				}
			}
`,
			expected: codebuild.Project{
				Metadata: defsecTypes.NewTestMetadata(),
				ArtifactSettings: codebuild.ArtifactSettings{
					Metadata:          defsecTypes.NewTestMetadata(),
					EncryptionEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
				SecondaryArtifactSettings: []codebuild.ArtifactSettings{
					{
						Metadata:          defsecTypes.NewTestMetadata(),
						EncryptionEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
					{
						Metadata:          defsecTypes.NewTestMetadata(),
						EncryptionEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults - encryption enabled",
			terraform: `
			resource "aws_codebuild_project" "codebuild" {
			}
`,
			expected: codebuild.Project{
				Metadata: defsecTypes.NewTestMetadata(),
				ArtifactSettings: codebuild.ArtifactSettings{
					Metadata:          defsecTypes.NewTestMetadata(),
					EncryptionEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptProject(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_codebuild_project" "codebuild" {
		artifacts {
			encryption_disabled = false
		}

		secondary_artifacts {
			encryption_disabled = false
		}

		secondary_artifacts {
			encryption_disabled = true
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Projects, 1)
	project := adapted.Projects[0]

	assert.Equal(t, 2, project.Metadata.Range().GetStartLine())
	assert.Equal(t, 14, project.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, project.ArtifactSettings.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, project.ArtifactSettings.Metadata.Range().GetEndLine())

	assert.Equal(t, 7, project.SecondaryArtifactSettings[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 9, project.SecondaryArtifactSettings[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 11, project.SecondaryArtifactSettings[1].Metadata.Range().GetStartLine())
	assert.Equal(t, 13, project.SecondaryArtifactSettings[1].Metadata.Range().GetEndLine())
}
