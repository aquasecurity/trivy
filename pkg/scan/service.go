package scan

import (
	"context"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Service is the main service that coordinates security scanning operations.
// It uses either local.Service or remote.Service as its backend implementation.
type Service struct {
	backend  Backend
	artifact artifact.Artifact
}

// Backend defines the interface for security scanning implementations.
// It can be either local.Service for standalone scanning or remote.Service
// for client/server mode scanning. The backend handles various types of
// security scanning including vulnerability, misconfiguration, secret,
// and license scanning.
type Backend interface {
	Scan(ctx context.Context, target, artifactKey string, blobKeys []string, options types.ScanOptions) (
		response types.ScanResponse, err error)
}

// NewService creates a new Service instance with the specified backend implementation
// and artifact handler.
func NewService(backend Backend, ar artifact.Artifact) Service {
	return Service{
		backend:  backend,
		artifact: ar,
	}
}

// ScanArtifact performs security scanning on the specified artifact.
// It first inspects the artifact to gather necessary information,
// then delegates the actual scanning to the configured backend implementation.
func (s Service) ScanArtifact(ctx context.Context, options types.ScanOptions) (types.Report, error) {
	artifactInfo, err := s.artifact.Inspect(ctx)
	if err != nil {
		return types.Report{}, xerrors.Errorf("failed analysis: %w", err)
	}
	defer func() {
		if err := s.artifact.Clean(artifactInfo); err != nil {
			log.Warn("Failed to clean the artifact",
				log.String("artifact", artifactInfo.Name), log.Err(err))
		}
	}()

	scanResponse, err := s.backend.Scan(ctx, artifactInfo.Name, artifactInfo.ID, artifactInfo.BlobIDs, options)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan failed: %w", err)
	}

	ptros := &scanResponse.OS
	if scanResponse.OS.Detected() && scanResponse.OS.Eosl {
		log.Warn("This OS version is no longer supported by the distribution",
			log.String("family", string(scanResponse.OS.Family)), log.String("version", scanResponse.OS.Name))
		log.Warn("The vulnerability detection may be insufficient because security updates are not provided")
	} else if !scanResponse.OS.Detected() {
		ptros = nil
	}

	// We don't need to include CreatedBy into Report
	for i := range scanResponse.Layers {
		scanResponse.Layers[i].CreatedBy = ""
	}

	return types.Report{
		SchemaVersion: report.SchemaVersion,
		CreatedAt:     clock.Now(ctx),
		ArtifactName:  artifactInfo.Name,
		ArtifactType:  artifactInfo.Type,
		Metadata: types.Metadata{
			OS: ptros,

			// Container image
			ImageID:     artifactInfo.ImageMetadata.ID,
			DiffIDs:     artifactInfo.ImageMetadata.DiffIDs,
			RepoTags:    artifactInfo.ImageMetadata.RepoTags,
			RepoDigests: artifactInfo.ImageMetadata.RepoDigests,
			ImageConfig: artifactInfo.ImageMetadata.ConfigFile,
			Size:        scanResponse.Layers.TotalSize(),
			Layers:      lo.Ternary(len(scanResponse.Layers) > 0, scanResponse.Layers, nil),

			// Git repository
			RepoURL:   artifactInfo.RepoMetadata.RepoURL,
			Branch:    artifactInfo.RepoMetadata.Branch,
			Tags:      artifactInfo.RepoMetadata.Tags,
			Commit:    artifactInfo.RepoMetadata.Commit,
			CommitMsg: artifactInfo.RepoMetadata.CommitMsg,
			Author:    artifactInfo.RepoMetadata.Author,
			Committer: artifactInfo.RepoMetadata.Committer,
		},
		Results: scanResponse.Results,
		BOM:     artifactInfo.BOM,
	}, nil
}
