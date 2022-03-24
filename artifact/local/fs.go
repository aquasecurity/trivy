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
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

const (
	parallel = 10
)

type Artifact struct {
	rootPath    string
	cache       cache.ArtifactCache
	walker      walker.FS
	analyzer    analyzer.AnalyzerGroup
	hookManager hook.Manager
	scanner     scanner.Scanner

	artifactOption      artifact.Option
	configScannerOption config.ScannerOption
}

func NewArtifact(rootPath string, c cache.ArtifactCache, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (artifact.Artifact, error) {
	// Register config analyzers
	if err := config.RegisterConfigAnalyzers(scannerOpt.FilePatterns); err != nil {
		return nil, xerrors.Errorf("config analyzer error: %w", err)
	}

	s, err := scanner.New(rootPath, scannerOpt.Namespaces, scannerOpt.PolicyPaths, scannerOpt.DataPaths, scannerOpt.Trace)
	if err != nil {
		return nil, xerrors.Errorf("scanner error: %w", err)
	}

	return Artifact{
		rootPath:    filepath.Clean(rootPath),
		cache:       c,
		walker:      walker.NewFS(buildAbsPaths(rootPath, artifactOpt.SkipFiles), buildAbsPaths(rootPath, artifactOpt.SkipDirs)),
		analyzer:    analyzer.NewAnalyzerGroup(artifactOpt.AnalyzerGroup, artifactOpt.DisabledAnalyzers),
		hookManager: hook.NewManager(artifactOpt.DisabledHooks),
		scanner:     s,

		artifactOption:      artifactOpt,
		configScannerOption: scannerOpt,
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
	result := new(analyzer.AnalysisResult)
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
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, directory, filePath, info, opener, opts); err != nil {
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

	// Scan config files
	misconfs, err := a.scanner.ScanConfigs(ctx, result.Configs)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("config scan error: %w", err)
	}

	blobInfo := types.BlobInfo{
		SchemaVersion:     types.BlobJSONSchemaVersion,
		OS:                result.OS,
		PackageInfos:      result.PackageInfos,
		Applications:      result.Applications,
		Misconfigurations: misconfs,
		SystemFiles:       result.SystemInstalledFiles,
	}

	if err = a.hookManager.CallHooks(&blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err = json.NewEncoder(h).Encode(blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	diffID := d.String()
	blobInfo.DiffID = diffID
	cacheKey, err := cache.CalcKey(diffID, a.analyzer.AnalyzerVersions(), a.hookManager.Versions(),
		a.artifactOption, a.configScannerOption)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", diffID, err)
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
