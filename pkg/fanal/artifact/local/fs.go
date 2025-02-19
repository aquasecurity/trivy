package local

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/google/wire"
	"github.com/opencontainers/go-digest"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/semaphore"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

var (
	ArtifactSet = wire.NewSet(
		walker.NewFS,
		wire.Bind(new(Walker), new(*walker.FS)),
		NewArtifact,
	)

	_ Walker = (*walker.FS)(nil)
)

type Walker interface {
	Walk(root string, opt walker.Option, fn walker.WalkFunc) error
}

type Artifact struct {
	rootPath       string
	logger         *log.Logger
	cache          cache.ArtifactCache
	walker         Walker
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption artifact.Option

	commitHash string // only set when the git repository is clean
}

func NewArtifact(rootPath string, c cache.ArtifactCache, w Walker, opt artifact.Option) (artifact.Artifact, error) {
	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler initialize error: %w", err)
	}

	a, err := analyzer.NewAnalyzerGroup(opt.AnalyzerOptions())
	if err != nil {
		return nil, xerrors.Errorf("analyzer group error: %w", err)
	}

	opt.Type = cmp.Or(opt.Type, artifact.TypeFilesystem)
	prefix := lo.Ternary(opt.Type == artifact.TypeRepository, "repo", "fs")

	art := Artifact{
		rootPath:       filepath.ToSlash(filepath.Clean(rootPath)),
		logger:         log.WithPrefix(prefix),
		cache:          c,
		walker:         w,
		analyzer:       a,
		handlerManager: handlerManager,
		artifactOption: opt,
	}

	art.logger.Debug("Analyzing...", log.String("root", art.rootPath),
		lo.Ternary(opt.Original != "", log.String("original", opt.Original), log.Nil))

	// Check if the directory is a git repository and clean
	if hash, err := gitCommitHash(art.rootPath); err == nil {
		art.logger.Debug("Using the latest commit hash for calculating cache key", log.String("commit_hash", hash))
		art.commitHash = hash
	} else if !errors.Is(err, git.ErrRepositoryNotExists) {
		// Only log if the file path is a git repository
		art.logger.Debug("Random cache key will be used", log.Err(err))
	}

	return art, nil
}

// gitCommitHash returns the latest commit hash if the git repository is clean, otherwise returns an error
func gitCommitHash(dir string) (string, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return "", xerrors.Errorf("failed to open git repository: %w", err)
	}

	// Get the working tree
	worktree, err := repo.Worktree()
	if err != nil {
		return "", xerrors.Errorf("failed to get worktree: %w", err)
	}

	// Get the current status
	status, err := worktree.Status()
	if err != nil {
		return "", xerrors.Errorf("failed to get status: %w", err)
	}

	if !status.IsClean() {
		return "", xerrors.New("repository is dirty")
	}

	// Get the HEAD commit hash
	head, err := repo.Head()
	if err != nil {
		return "", xerrors.Errorf("failed to get HEAD: %w", err)
	}

	return head.Hash().String(), nil
}

func (a Artifact) Inspect(ctx context.Context) (artifact.Reference, error) {
	// Calculate cache key
	cacheKey, err := a.calcCacheKey()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
	}

	// Check if the cache exists only when it's a clean git repository
	if a.commitHash != "" {
		_, missingBlobs, err := a.cache.MissingBlobs(cacheKey, []string{cacheKey})
		if err != nil {
			return artifact.Reference{}, xerrors.Errorf("unable to get missing blob: %w", err)
		}

		if len(missingBlobs) == 0 {
			// Cache hit
			a.logger.DebugContext(ctx, "Cache hit", log.String("key", cacheKey))
			return artifact.Reference{
				Name:    cmp.Or(a.artifactOption.Original, a.rootPath),
				Type:    a.artifactOption.Type,
				ID:      cacheKey,
				BlobIDs: []string{cacheKey},
			}, nil
		}
	}

	var wg sync.WaitGroup
	result := analyzer.NewAnalysisResult()
	limit := semaphore.New(a.artifactOption.Parallel)
	opts := analyzer.AnalysisOptions{
		Offline:      a.artifactOption.Offline,
		FileChecksum: a.artifactOption.FileChecksum,
	}

	// Prepare filesystem for post analysis
	composite, err := a.analyzer.PostAnalyzerFS()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to prepare filesystem for post analysis: %w", err)
	}
	defer composite.Cleanup()

	err = a.walker.Walk(a.rootPath, a.artifactOption.WalkerOption, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		dir := a.rootPath

		// When the directory is the same as the filePath, a file was given
		// instead of a directory, rewrite the file path and directory in this case.
		if filePath == "." {
			dir, filePath = path.Split(a.rootPath)
		}

		if err := a.analyzer.AnalyzeFile(ctx, &wg, limit, result, dir, filePath, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", filePath, err)
		}

		// Skip post analysis if the file is not required
		analyzerTypes := a.analyzer.RequiredPostAnalyzers(filePath, info)
		if len(analyzerTypes) == 0 {
			return nil
		}

		// Build filesystem for post analysis
		if err := composite.CreateLink(analyzerTypes, dir, filePath, filepath.Join(dir, filePath)); err != nil {
			return xerrors.Errorf("failed to create link: %w", err)
		}

		return nil
	})
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("walk filesystem: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Post-analysis
	if err = a.analyzer.PostAnalyze(ctx, composite, result, opts); err != nil {
		return artifact.Reference{}, xerrors.Errorf("post analysis error: %w", err)
	}

	// Sort the analysis result for consistent results
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion:     types.BlobJSONSchemaVersion,
		OS:                result.OS,
		Repository:        result.Repository,
		PackageInfos:      result.PackageInfos,
		Applications:      result.Applications,
		Misconfigurations: result.Misconfigurations,
		Secrets:           result.Secrets,
		Licenses:          result.Licenses,
		CustomResources:   result.CustomResources,
	}

	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	// get hostname
	var hostName string
	b, err := os.ReadFile(filepath.Join(a.rootPath, "etc", "hostname"))
	if err == nil && len(b) != 0 {
		hostName = strings.TrimSpace(string(b))
	} else {
		target := cmp.Or(a.artifactOption.Original, a.rootPath)
		hostName = filepath.ToSlash(target) // To slash for Windows
	}

	return artifact.Reference{
		Name:    hostName,
		Type:    a.artifactOption.Type,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a Artifact) Clean(reference artifact.Reference) error {
	// Don't delete cache if it's a clean git repository
	if a.commitHash != "" {
		return nil
	}
	return a.cache.DeleteBlobs(reference.BlobIDs)
}

func (a Artifact) calcCacheKey() (string, error) {
	// If this is a clean git repository, use the commit hash as cache key
	if a.commitHash != "" {
		return cache.CalcKey(a.commitHash, a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	}

	// For non-git repositories or dirty git repositories, use UUID as cache key
	h := sha256.New()
	if _, err := h.Write([]byte(uuid.New().String())); err != nil {
		return "", xerrors.Errorf("sha256 calculation error: %w", err)
	}

	// Format as sha256 digest
	d := digest.NewDigest(digest.SHA256, h)
	return d.String(), nil
}
