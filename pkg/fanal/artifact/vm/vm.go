package vm

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
)

type Artifact struct {
	filePath       string
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption artifact.Option
}

func (a Artifact) Inspect(ctx context.Context) (reference types.ArtifactReference, err error) {
	// TODO implement me
	panic("implement me")
}

func (a Artifact) Clean(reference types.ArtifactReference) error {
	// TODO implement me
	panic("implement me")
}

func NewArtifact(filePath string, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	return Artifact{
		filePath:       filepath.Clean(filePath),
		cache:          c,
		artifactOption: opt,
	}, nil
}
