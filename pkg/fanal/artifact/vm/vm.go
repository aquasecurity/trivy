package vm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru"
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
	cacheSize = 2048
)

type Artifact struct {
	filePath       string
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager
	walker         walker.VM
	storageOption  storage.Option

	artifactOption artifact.Option
}

var (
	cleanCacheFlag = "deleteCache"
)

func (a Artifact) Inspect(ctx context.Context) (reference types.ArtifactReference, err error) {

	s, err := storage.Open(a.filePath, a.storageOption, ctx)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to open storage: %w", err)
	}
	defer s.Close()

	// For EBS scan, if cache exists in fanal.db, use it.
	if s.Type == storage.TypeEBS {
		cacheKey, err := a.vmCacheKey(a.filePath)
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

	lruCache, err := lru.New(cacheSize)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to create new lru cache: %w", err)
	}
	defer lruCache.Purge()

	result := analyzer.NewAnalysisResult()
	// TODO: Always walk from the root directory. Consider whether there is a need to be able to set optional
	err = a.walker.Walk(s.Reader, lruCache, "/", func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
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

	var cacheKey string
	if s.Type == storage.TypeFile {
		cacheKey, err = a.calcCacheKey(blobInfo)
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to calculate a file cache key: %w", err)
		}

		// If file is targeted, do not cache
		cacheKey = fmt.Sprintf("%s:%s", cleanCacheFlag, cacheKey)
	} else if s.Type == storage.TypeEBS {
		cacheKey, err = a.vmCacheKey(a.filePath)
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to calculate a vm cache key: %w", err)
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
	if !strings.HasPrefix(reference.ID, cleanCacheFlag) {
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

	return Artifact{
		filePath:       filepath.Clean(filePath),
		cache:          c,
		handlerManager: handlerManager,
		analyzer:       a,
		walker:         walker.NewVM(opt.SkipFiles, opt.SkipDirs, opt.Slow),
		storageOption:  storage.Option{},
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
