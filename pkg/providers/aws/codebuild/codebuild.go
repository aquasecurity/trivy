package codebuild

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	Metadata                  defsecTypes.MisconfigMetadata
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	Metadata          defsecTypes.MisconfigMetadata
	EncryptionEnabled defsecTypes.BoolValue
}
