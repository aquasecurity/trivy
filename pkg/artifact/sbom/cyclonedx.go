package sbom

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"

	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/handler"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
)

var (
	ArtifactCycloneDX types.ArtifactType = "cyclonedx"
)

type Artifact struct {
	filePath       string
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager
	sbomParser     sbom.Parser

	artifactOption      artifact.Option
	configScannerOption config.ScannerOption
}

func NewArtifact(artifactType, filePath string, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	var parser sbom.Parser
	switch artifactType {
	case string(ArtifactCycloneDX):
		parser = cyclonedx.New(filePath)
	}
	return Artifact{
		filePath:       filepath.Clean(filePath),
		sbomParser:     parser,
		cache:          c,
		artifactOption: opt,
	}, nil
}

func (a Artifact) Inspect(_ context.Context) (types.ArtifactReference, error) {
	f, err := os.Open(a.filePath)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to open sbom file error: %w", err)
	}
	defer f.Close()

	bomID, o, pkgInfos, apps, err := a.sbomParser.Parse(f)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to get blob info: %w", err)
	}
	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		Applications:  apps,
		PackageInfos:  pkgInfos,
		OS:            o,
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	return types.ArtifactReference{
		Name:    bomID,
		Type:    a.Type(),
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a Artifact) Type() types.ArtifactType {
	switch a.sbomParser.Type() {
	case cyclonedx.FormatCycloneDX:
		return ArtifactCycloneDX
	default:
		return ""
	}
}

func (a Artifact) Clean(reference types.ArtifactReference) error {
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
