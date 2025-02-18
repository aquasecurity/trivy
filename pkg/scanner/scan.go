package scanner

import (
	"context"

	"github.com/google/wire"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	aimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	flocal "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/repo"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
)

///////////////
// Standalone
///////////////

// StandaloneSuperSet is used in the standalone mode
var StandaloneSuperSet = wire.NewSet(
	// Cache
	cache.New,
	wire.Bind(new(cache.ArtifactCache), new(cache.Cache)),
	wire.Bind(new(cache.LocalArtifactCache), new(cache.Cache)),

	local.SuperSet,
	wire.Bind(new(Driver), new(local.Scanner)),
	NewScanner,
)

// StandaloneDockerSet binds docker dependencies
var StandaloneDockerSet = wire.NewSet(
	image.NewContainerImage,
	aimage.NewArtifact,
	StandaloneSuperSet,
)

// StandaloneArchiveSet binds archive scan dependencies
var StandaloneArchiveSet = wire.NewSet(
	image.NewArchiveImage,
	aimage.NewArtifact,
	StandaloneSuperSet,
)

// StandaloneFilesystemSet binds filesystem dependencies
var StandaloneFilesystemSet = wire.NewSet(
	flocal.ArtifactSet,
	StandaloneSuperSet,
)

// StandaloneRepositorySet binds repository dependencies
var StandaloneRepositorySet = wire.NewSet(
	repo.ArtifactSet,
	StandaloneSuperSet,
)

// StandaloneSBOMSet binds sbom dependencies
var StandaloneSBOMSet = wire.NewSet(
	sbom.NewArtifact,
	StandaloneSuperSet,
)

// StandaloneVMSet binds vm dependencies
var StandaloneVMSet = wire.NewSet(
	vm.ArtifactSet,
	StandaloneSuperSet,
)

/////////////////
// Client/Server
/////////////////

// RemoteSuperSet is used in the client mode
var RemoteSuperSet = wire.NewSet(
	// Cache
	cache.NewRemoteCache,
	wire.Bind(new(cache.ArtifactCache), new(*cache.RemoteCache)), // No need for LocalArtifactCache

	client.NewScanner,
	wire.Value([]client.Option(nil)),
	wire.Bind(new(Driver), new(client.Scanner)),
	NewScanner,
)

// RemoteFilesystemSet binds filesystem dependencies for client/server mode
var RemoteFilesystemSet = wire.NewSet(
	flocal.ArtifactSet,
	RemoteSuperSet,
)

// RemoteRepositorySet binds repository dependencies for client/server mode
var RemoteRepositorySet = wire.NewSet(
	repo.ArtifactSet,
	RemoteSuperSet,
)

// RemoteSBOMSet binds sbom dependencies for client/server mode
var RemoteSBOMSet = wire.NewSet(
	sbom.NewArtifact,
	RemoteSuperSet,
)

// RemoteVMSet binds vm dependencies for client/server mode
var RemoteVMSet = wire.NewSet(
	vm.ArtifactSet,
	RemoteSuperSet,
)

// RemoteDockerSet binds remote docker dependencies
var RemoteDockerSet = wire.NewSet(
	aimage.NewArtifact,
	image.NewContainerImage,
	RemoteSuperSet,
)

// RemoteArchiveSet binds remote archive dependencies
var RemoteArchiveSet = wire.NewSet(
	aimage.NewArtifact,
	image.NewArchiveImage,
	RemoteSuperSet,
)

// Scanner implements the Artifact and Driver operations
type Scanner struct {
	driver   Driver
	artifact artifact.Artifact
}

// Driver defines operations of scanner
type Driver interface {
	Scan(ctx context.Context, target, artifactKey string, blobKeys []string, options types.ScanOptions) (
		response types.ScanResponse, err error)
}

// NewScanner is the factory method of Scanner
func NewScanner(driver Driver, ar artifact.Artifact) Scanner {
	return Scanner{
		driver:   driver,
		artifact: ar,
	}
}

// ScanArtifact scans the artifacts and returns results
func (s Scanner) ScanArtifact(ctx context.Context, options types.ScanOptions) (types.Report, error) {
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
	scanResponse, err := s.driver.Scan(ctx, artifactInfo.Name, artifactInfo.ID, artifactInfo.BlobIDs, options)
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

	// We don't need to include this info into Report
	for i := range scanResponse.LayersMetadata {
		scanResponse.LayersMetadata[i].CreatedBy = ""
		scanResponse.LayersMetadata[i].OpaqueDirs = nil
		scanResponse.LayersMetadata[i].WhiteoutFiles = nil
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
			Size:        scanResponse.LayersMetadata.TotalSize(),
			Layers:      lo.Ternary(!scanResponse.LayersMetadata.Empty(), scanResponse.LayersMetadata, nil),
		},
		Results: scanResponse.Results,
		BOM:     artifactInfo.BOM,
	}, nil
}
