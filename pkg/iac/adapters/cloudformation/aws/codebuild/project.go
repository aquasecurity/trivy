package codebuild

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/codebuild"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getProjects(ctx parser.FileContext) (projects []codebuild.Project) {

	projectResources := ctx.GetResourcesByType("AWS::CodeBuild::Project")

	for _, r := range projectResources {
		project := codebuild.Project{
			Metadata:                  r.Metadata(),
			ArtifactSettings:          getArtifactSettings(r),
			SecondaryArtifactSettings: getSecondaryArtifactSettings(r),
		}

		projects = append(projects, project)
	}

	return projects
}

func getSecondaryArtifactSettings(r *parser.Resource) (secondaryArtifacts []codebuild.ArtifactSettings) {
	secondaryArtifactsList := r.GetProperty("SecondaryArtifacts")
	if secondaryArtifactsList.IsNil() || !secondaryArtifactsList.IsList() {
		return
	}

	for _, a := range secondaryArtifactsList.AsList() {
		settings := codebuild.ArtifactSettings{
			Metadata:          secondaryArtifactsList.Metadata(),
			EncryptionEnabled: types.BoolDefault(true, secondaryArtifactsList.Metadata()),
		}
		encryptionDisabled := a.GetBoolProperty("EncryptionDisabled")
		if m := encryptionDisabled.GetMetadata(); m.IsResolvable() && !m.IsDefault() {
			settings.EncryptionEnabled = encryptionDisabled.Invert()
		}
		secondaryArtifacts = append(secondaryArtifacts, settings)
	}

	return secondaryArtifacts
}

func getArtifactSettings(r *parser.Resource) codebuild.ArtifactSettings {

	settings := codebuild.ArtifactSettings{
		Metadata:          r.Metadata(),
		EncryptionEnabled: types.BoolDefault(true, r.Metadata()),
	}

	if encryptionDisabled := r.GetBoolProperty("Artifacts.EncryptionDisabled"); encryptionDisabled.GetMetadata().IsResolvable() {
		settings.EncryptionEnabled = encryptionDisabled.Invert()
	}

	return settings
}
