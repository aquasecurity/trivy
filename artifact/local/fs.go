package local

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	digest "github.com/opencontainers/go-digest"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/analyzer/secret"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/handler"
	_ "github.com/aquasecurity/fanal/handler/all"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

const (
	parallel = 10
)

type Artifact struct {
	rootPath       string
	cache          cache.ArtifactCache
	walker         walker.FS
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption artifact.Option
}

func NewArtifact(rootPath string, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	// Register config analyzers
	if err := config.RegisterConfigAnalyzers(opt.MisconfScannerOption.FilePatterns); err != nil {
		return nil, xerrors.Errorf("config analyzer error: %w", err)
	}

	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler initialize error: %w", err)
	}

	// Register secret analyzer
	if err = secret.RegisterSecretAnalyzer(opt.SecretScannerOption); err != nil {
		return nil, xerrors.Errorf("secret scanner error: %w", err)
	}

	return Artifact{
		rootPath:       filepath.Clean(rootPath),
		cache:          c,
		walker:         walker.NewFS(buildAbsPaths(rootPath, opt.SkipFiles), buildAbsPaths(rootPath, opt.SkipDirs)),
		analyzer:       analyzer.NewAnalyzerGroup(opt.AnalyzerGroup, opt.DisabledAnalyzers),
		handlerManager: handlerManager,

		artifactOption: opt,
	}, nil
}

func buildAbsPaths(base string, paths []string) []string {
	var absPaths []string
	for _, path := range paths {
		if filepath.IsAbs(path) {
			absPaths = append(absPaths, path)
		} else {
			absPaths = append(absPaths, filepath.Join(base, path))
		}
	}
	return absPaths
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	var wg sync.WaitGroup
	result := analyzer.NewAnalysisResult()
	limit := semaphore.NewWeighted(parallel)

	err := a.walker.Walk(a.rootPath, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		directory := a.rootPath

		// When the directory is the same as the filePath, a file was given
		// instead of a directory, rewrite the directory in this case.
		if a.rootPath == filePath {
			directory = filepath.Dir(a.rootPath)
		}

		// For exported rootfs (e.g. images/alpine/etc/alpine-release)
		filePath, err := filepath.Rel(directory, filePath)
		if err != nil {
			return xerrors.Errorf("filepath rel (%s): %w", filePath, err)
		}

		opts := analyzer.AnalysisOptions{Offline: a.artifactOption.Offline}
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, directory, filePath, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("walk filesystem: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Sort the analysis result for consistent results
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		OS:            result.OS,
		Repository:    result.Repository,
		PackageInfos:  result.PackageInfos,
		Applications:  result.Applications,
		Secrets:       result.Secrets,
	}

	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	// get hostname
	var hostName string
	b, err := os.ReadFile(filepath.Join(a.rootPath, "etc", "hostname"))
	if err == nil && string(b) != "" {
		hostName = strings.TrimSpace(string(b))
	} else {
		hostName = a.rootPath
	}

	return types.ArtifactReference{
		Name:    hostName,
		Type:    types.ArtifactFilesystem,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
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
