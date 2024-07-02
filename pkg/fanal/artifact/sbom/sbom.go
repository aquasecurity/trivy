package sbom

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom"
)

type Artifact struct {
	filePath       string
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption artifact.Option
}

func NewArtifact(filePath string, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	return Artifact{
		filePath:       filepath.Clean(filePath),
		cache:          c,
		artifactOption: opt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (artifact.Reference, error) {
	f, err := os.Open(a.filePath)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to open sbom file error: %w", err)
	}
	defer f.Close()

	// Format auto-detection
	format, err := sbom.DetectFormat(f)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to detect SBOM format: %w", err)
	}
	log.Info("Detected SBOM format", log.String("format", string(format)))

	ctx = log.WithContextAttrs(ctx, log.FilePath(a.filePath))
	bom, err := sbom.Decode(ctx, f, format)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("SBOM decode error: %w", err)
	}

	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		OS:            lo.FromPtr(bom.Metadata.OS),
		PackageInfos:  bom.Packages,
		Applications:  bom.Applications,
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	var artifactType artifact.Type
	switch format {
	case sbom.FormatCycloneDXJSON, sbom.FormatCycloneDXXML, sbom.FormatAttestCycloneDXJSON, sbom.FormatLegacyCosignAttestCycloneDXJSON:
		artifactType = artifact.TypeCycloneDX
	case sbom.FormatSPDXTV, sbom.FormatSPDXJSON:
		artifactType = artifact.TypeSPDX

	}

	return artifact.Reference{
		Name:    a.filePath,
		Type:    artifactType,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},

		// Keep an original report
		BOM: bom.BOM,
	}, nil
}

func (a Artifact) Clean(reference artifact.Reference) error {
	return a.cache.DeleteBlobs(reference.BlobIDs)
}

func (a Artifact) calcCacheKey(blobInfo types.BlobInfo) (string, error) {
	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(blobInfo); err != nil {
		return "", xerrors.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	cacheKey, err := cache.CalcKey(d.String(), a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", xerrors.Errorf("cache key: %w", err)
	}

	return cacheKey, nil
}
