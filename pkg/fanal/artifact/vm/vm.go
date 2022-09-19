package vm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"golang.org/x/sync/semaphore"
	"os"
	"path/filepath"
	"sync"

	"github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	// Register Filesystem
	_ "github.com/aquasecurity/trivy/pkg/fanal/vm/filesystem/xfs"
	// Register Reader
	_ "github.com/aquasecurity/trivy/pkg/fanal/vm/vmdk"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

const (
	parallel = 5
)

type Artifact struct {
	filePath       string
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager
	walker         walker.VM

	artifactOption artifact.Option
}

func (a Artifact) Inspect(ctx context.Context) (reference types.ArtifactReference, err error) {
	result := analyzer.NewAnalysisResult()

	v, err := vm.New(a.filePath)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("new virtual machine error: %w", err)
	}
	defer v.Close()

	var wg sync.WaitGroup
	limit := semaphore.NewWeighted(parallel)

	// TODO: Always walk from the root directory. Consider whether there is a need to be able to set optional
	err = a.walker.Walk(v.SectionReader, "/", func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		opts := analyzer.AnalysisOptions{Offline: a.artifactOption.Offline}
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "/", filePath, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("walk vm error: %w", err)
	}
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion:   types.BlobJSONSchemaVersion,
		OS:              result.OS,
		Repository:      result.Repository,
		PackageInfos:    result.PackageInfos,
		Applications:    result.Applications,
		Secrets:         result.Secrets,
		Licenses:        result.Licenses,
		CustomResources: result.CustomResources,
	}

	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	// TODO: use virtual machine image sha:256 key..?
	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	return types.ArtifactReference{
		Name:    a.filePath,
		Type:    types.ArtifactVM,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a Artifact) Clean(reference types.ArtifactReference) error {
	return a.cache.DeleteBlobs(reference.BlobIDs)
}

func NewArtifact(filePath string, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler init error: %w", err)
	}
	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		Group:               opt.AnalyzerGroup,
		FilePatterns:        opt.FilePatterns,
		DisabledAnalyzers:   opt.DisabledAnalyzers,
		SecretScannerOption: opt.SecretScannerOption,
	})
	if err != nil {
		return nil, xerrors.Errorf("analyzer group error: %w", err)
	}

	return Artifact{
		filePath:       filepath.Clean(filePath),
		cache:          c,
		handlerManager: handlerManager,
		analyzer:       a,
		walker:         walker.NewVM(opt.SkipFiles, opt.SkipDirs),

		artifactOption: opt,
	}, nil
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
