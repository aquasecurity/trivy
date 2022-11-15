package vm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hashicorp/golang-lru/simplelru"
	ebsfile "github.com/masahiro331/go-ebs-file"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/storage"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	parallel  = 5
	cacheSize = 40 << 20 // 40 MB
)

type Artifact struct {
	filePath       string
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager
	walker         walker.VM
	store          storage.Storage
	lruCache       simplelru.LRUCache

	artifactOption artifact.Option
}

func (a Artifact) Inspect(ctx context.Context) (reference types.ArtifactReference, err error) {
	result := analyzer.NewAnalysisResult()

	defer a.lruCache.Purge()

	sr, cacheKey, err := a.store.Open(a.filePath, ctx)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to open storage: %w", err)
	}
	defer a.store.Close()

	if cacheKey != "" {
		cacheKey, err = a.vmCacheKey(cacheKey)
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to create vm cache key: %w", err)
		}
		missingVMCache, _, err := a.cache.MissingBlobs(cacheKey, []string{cacheKey})
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to missing blobs from cache: %w", err)
		}
		if missingVMCache {
			log.Logger.Debugf("Missing virtual machine cache: %s", cacheKey)
		} else {
			return types.ArtifactReference{
				Name:    a.filePath,
				Type:    types.ArtifactVM,
				ID:      cacheKey, // use a cache key as pseudo artifact ID
				BlobIDs: []string{cacheKey},
			}, nil
		}
	}

	var wg sync.WaitGroup
	limit := semaphore.NewWeighted(parallel)
	if a.artifactOption.Slow {
		limit = semaphore.NewWeighted(1)
	}

	// TODO: Always walk from the root directory. Consider whether there is a need to be able to set optional
	err = a.walker.Walk(sr, a.lruCache, "/", func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		opts := analyzer.AnalysisOptions{Offline: a.artifactOption.Offline}
		path := strings.TrimPrefix(filePath, "/")
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "/", path, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", path, err)
		}
		return nil
	})

	// Wait for all the goroutine to finish.
	wg.Wait()

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

	if cacheKey == "" {
		cacheKey, err = a.calcCacheKey(blobInfo)
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
		}
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}
	info := types.ArtifactInfo{
		SchemaVersion: types.ArtifactJSONSchemaVersion,
	}
	if err = a.cache.PutArtifact(cacheKey, info); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return types.ArtifactReference{
		Name:    a.filePath,
		Type:    types.ArtifactVM,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a Artifact) Clean(reference types.ArtifactReference) error {
	if strings.HasPrefix(a.store.Type(), storage.TypeEBS) {
		return nil
	}
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

	lruCache, err := lru.New(cacheSize)
	if err != nil {
		return nil, xerrors.Errorf("failed to create new lru cache: %w", err)
	}
	s, err := storage.NewStorage(filePath, ebsfile.Option{}, lruCache)
	if err != nil {
		return nil, xerrors.Errorf("failed to new storage: %w", err)
	}
	return Artifact{
		filePath:       filepath.Clean(filePath),
		cache:          c,
		handlerManager: handlerManager,
		analyzer:       a,
		walker:         walker.NewVM(opt.SkipFiles, opt.SkipDirs, opt.Slow),
		lruCache:       lruCache,
		store:          s,

		artifactOption: opt,
	}, nil
}

func (a Artifact) vmCacheKey(key string) (string, error) {
	s, err := cache.CalcKey(key, a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", xerrors.Errorf("failed to calculate cache key: %w", err)
	}
	return s, nil
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
