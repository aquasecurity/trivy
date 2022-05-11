package codebuild

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	types.Metadata
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	types.Metadata
	EncryptionEnabled types.BoolValue
}
