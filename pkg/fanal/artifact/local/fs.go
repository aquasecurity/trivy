package local

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/semaphore"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

const artifactVersion = 0

var _ Walker = (*walker.FS)(nil)

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

	isClean      bool                  // whether git repository is clean (for caching)
	repoMetadata artifact.RepoMetadata // git repository metadata
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

	opt.Type = cmp.Or(opt.Type, types.TypeFilesystem)
	prefix := lo.Ternary(opt.Type == types.TypeRepository, "repo", "fs")

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

	// Check if the directory is a git repository and extract metadata
	if art.isClean, art.repoMetadata, err = extractGitInfo(art.rootPath); err == nil {
		// If git info is detected, change artifact type to repository
		art.artifactOption.Type = types.TypeRepository
		if art.isClean {
			art.logger.Debug("Using the latest commit hash for calculating cache key",
				log.String("commit_hash", art.repoMetadata.Commit))
		} else {
			art.logger.Debug("Repository is dirty, random cache key will be used")
		}
	} else if !errors.Is(err, git.ErrRepositoryNotExists) {
		// Only log if the file path is a git repository
		art.logger.Debug("Random cache key will be used", log.Err(err))
	}

	return art, nil
}

// extractGitInfo extracts git repository information including clean status and metadata
// Returns clean status (for caching), metadata, and error
func extractGitInfo(dir string) (bool, artifact.RepoMetadata, error) {
	var metadata artifact.RepoMetadata

	repo, err := git.PlainOpen(dir)
	if err != nil {
		return false, metadata, xerrors.Errorf("failed to open git repository: %w", err)
	}

	// Get HEAD commit
	head, err := repo.Head()
	if err != nil {
		return false, metadata, xerrors.Errorf("failed to get HEAD: %w", err)
	}

	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return false, metadata, xerrors.Errorf("failed to get commit object: %w", err)
	}

	// Extract basic commit metadata
	metadata.Commit = head.Hash().String()
	metadata.CommitMsg = strings.TrimSpace(commit.Message)
	metadata.Author = commit.Author.String()
	metadata.Committer = commit.Committer.String()

	// Get branch name
	if head.Name().IsBranch() {
		metadata.Branch = head.Name().Short()
	}

	// Get all tag names that point to HEAD
	if tags, err := repo.Tags(); err == nil {
		var headTags []string
		_ = tags.ForEach(func(tag *plumbing.Reference) error {
			if tag.Hash() == head.Hash() {
				headTags = append(headTags, tag.Name().Short())
			}
			return nil
		})
		metadata.Tags = headTags
	}

	// Get repository URL - prefer upstream, fallback to origin
	remoteConfig, err := repo.Remote("upstream")
	if err != nil {
		remoteConfig, err = repo.Remote("origin")
	}
	if err == nil && len(remoteConfig.Config().URLs) > 0 {
		metadata.RepoURL = sanitizeRemoteURL(remoteConfig.Config().URLs[0])
	}

	// Check if repository is clean for caching purposes
	worktree, err := repo.Worktree()
	if err != nil {
		return false, metadata, xerrors.Errorf("failed to get worktree: %w", err)
	}

	status, err := worktree.Status()
	if err != nil {
		return false, metadata, xerrors.Errorf("failed to get status: %w", err)
	}

	// Return clean status and metadata
	return status.IsClean(), metadata, nil
}

func (a Artifact) Inspect(ctx context.Context) (artifact.Reference, error) {
	// Calculate cache key
	cacheKey, err := a.calcCacheKey()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
	}

	// Check if the cache exists only when it's a clean git repository
	if a.isClean && a.repoMetadata.Commit != "" {
		_, missingBlobs, err := a.cache.MissingBlobs(ctx, cacheKey, []string{cacheKey})
		if err != nil {
			return artifact.Reference{}, xerrors.Errorf("unable to get missing blob: %w", err)
		}

		if len(missingBlobs) == 0 {
			// Cache hit
			a.logger.DebugContext(ctx, "Cache hit", log.String("key", cacheKey))
			return artifact.Reference{
				Name:         cmp.Or(a.artifactOption.Original, a.rootPath),
				Type:         a.artifactOption.Type,
				ID:           cacheKey,
				BlobIDs:      []string{cacheKey},
				RepoMetadata: a.repoMetadata,
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

	// Use static paths instead of traversing the filesystem when all analyzers implement StaticPathAnalyzer
	// so that we can analyze files faster
	if paths, canUseStaticPaths := a.analyzer.StaticPaths(a.artifactOption.DisabledAnalyzers); canUseStaticPaths {
		// Analyze files in static paths
		a.logger.Debug("Analyzing files in static paths")
		if err = a.analyzeWithStaticPaths(ctx, &wg, limit, result, composite, opts, paths); err != nil {
			return artifact.Reference{}, xerrors.Errorf("analyze with static paths: %w", err)
		}
	} else {
		// Analyze files by traversing the root directory
		if err = a.analyzeWithRootDir(ctx, &wg, limit, result, composite, opts); err != nil {
			return artifact.Reference{}, xerrors.Errorf("analyze with traversal: %w", err)
		}
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

		// For Red Hat
		BuildInfo: result.BuildInfo,
	}

	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	if err = a.cache.PutBlob(ctx, cacheKey, blobInfo); err != nil {
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
		Name:         hostName,
		Type:         a.artifactOption.Type,
		ID:           cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs:      []string{cacheKey},
		RepoMetadata: a.repoMetadata,
	}, nil
}

func (a Artifact) analyzeWithRootDir(ctx context.Context, wg *sync.WaitGroup, limit *semaphore.Weighted,
	result *analyzer.AnalysisResult, composite *analyzer.CompositeFS, opts analyzer.AnalysisOptions) error {

	root := a.rootPath
	relativePath := ""

	// When the root path is a file, rewrite the root path and relative path
	if fsutils.FileExists(a.rootPath) {
		root, relativePath = path.Split(a.rootPath)
	}
	return a.analyzeWithTraversal(ctx, root, relativePath, wg, limit, result, composite, opts)
}

// analyzeWithStaticPaths analyzes files using static paths from analyzers
func (a Artifact) analyzeWithStaticPaths(ctx context.Context, wg *sync.WaitGroup, limit *semaphore.Weighted,
	result *analyzer.AnalysisResult, composite *analyzer.CompositeFS, opts analyzer.AnalysisOptions,
	staticPaths []string) error {

	// Process each static path
	for _, relativePath := range staticPaths {
		if err := a.analyzeWithTraversal(ctx, a.rootPath, relativePath, wg, limit, result, composite, opts); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return xerrors.Errorf("analyze with traversal: %w", err)
		}
	}

	return nil
}

// analyzeWithTraversal analyzes files by traversing the entire filesystem
func (a Artifact) analyzeWithTraversal(ctx context.Context, root, relativePath string, wg *sync.WaitGroup, limit *semaphore.Weighted,
	result *analyzer.AnalysisResult, composite *analyzer.CompositeFS, opts analyzer.AnalysisOptions) error {

	return a.walker.Walk(filepath.Join(root, relativePath), a.artifactOption.WalkerOption, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		filePath = path.Join(relativePath, filePath)
		if err := a.analyzer.AnalyzeFile(ctx, wg, limit, result, root, filePath, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", filePath, err)
		}

		// Skip post analysis if the file is not required
		analyzerTypes := a.analyzer.RequiredPostAnalyzers(filePath, info)
		if len(analyzerTypes) == 0 {
			return nil
		}

		// Build filesystem for post analysis
		if err := composite.CreateLink(analyzerTypes, root, filePath, filepath.Join(root, filePath)); err != nil {
			return xerrors.Errorf("failed to create link: %w", err)
		}

		return nil
	})
}

func (a Artifact) Clean(reference artifact.Reference) error {
	// Don't delete cache if it's a clean git repository
	if a.isClean && a.repoMetadata.Commit != "" {
		return nil
	}
	return a.cache.DeleteBlobs(context.TODO(), reference.BlobIDs)
}

func (a Artifact) calcCacheKey() (string, error) {
	// If this is a clean git repository, use the commit hash as cache key
	if a.isClean && a.repoMetadata.Commit != "" {
		return cache.CalcKey(a.repoMetadata.Commit, artifactVersion, a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
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

// sanitizeRemoteURL removes credentials (userinfo) from URLs.
func sanitizeRemoteURL(gitUrl string) string {
	// Only attempt sanitization for URLs with an explicit scheme.
	if !strings.Contains(gitUrl, "://") {
		return gitUrl
	}

	// Try URL parsing first.
	if u, err := url.Parse(gitUrl); err == nil {
		// Clear userinfo (username:password)
		u.User = nil
		gitUrl = u.String()
	}

	return gitUrl
}
