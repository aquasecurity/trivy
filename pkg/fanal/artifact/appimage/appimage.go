// Package appimage implements scanning of AppImage files.
// AppImage is a universal Linux application format that embeds a SquashFS
// filesystem inside an ELF binary. This package provides the artifact
// implementation for the "trivy appimage" subcommand.
package appimage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"

	"github.com/opencontainers/go-digest"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/semaphore"
)

const artifactVersion = 0

// Walker is the interface that the AppImage artifact uses to walk a SquashFS
// SectionReader. It mirrors the vm.Walker interface.
type Walker interface {
	Walk(*io.SectionReader, string, walker.Option, walker.WalkFunc) error
}

// Artifact represents an AppImage file artifact ready for scanning.
type Artifact struct {
	filePath string
	file     *os.File
	reader   *io.SectionReader // SectionReader over the SquashFS payload

	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager
	walker         Walker
	artifactOption artifact.Option
}

// NewArtifact opens the given AppImage file, validates the AppImage magic,
// locates the embedded SquashFS payload, and returns a ready-to-inspect Artifact.
// Returns an error (wrapping walker.ErrNotAppImage) if the file is not a valid
// AppImage Type 2 file.
func NewArtifact(filePath string, c cache.ArtifactCache, w Walker, opt artifact.Option) (*Artifact, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("appimage open error: %w", err)
	}

	if !walker.IsAppImage(f) {
		_ = f.Close()
		return nil, xerrors.Errorf("%s: not an AppImage Type 2 file", filePath)
	}

	sqfsOffset, err := walker.FindSquashFSOffset(f)
	if err != nil {
		_ = f.Close()
		return nil, xerrors.Errorf("appimage squashfs offset error: %w", err)
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, xerrors.Errorf("appimage stat error: %w", err)
	}

	sqfsSize := fi.Size() - sqfsOffset
	reader := io.NewSectionReader(f, sqfsOffset, sqfsSize)
	log.Debug("AppImage squashfs payload", log.String("file", filePath),
		log.Int64("offset", sqfsOffset), log.Int64("size", sqfsSize))

	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		_ = f.Close()
		return nil, xerrors.Errorf("handler init error: %w", err)
	}

	a, err := analyzer.NewAnalyzerGroup(opt.AnalyzerOptions())
	if err != nil {
		_ = f.Close()
		return nil, xerrors.Errorf("analyzer group error: %w", err)
	}

	return &Artifact{
		filePath:       filePath,
		file:           f,
		reader:         reader,
		cache:          c,
		analyzer:       a,
		handlerManager: handlerManager,
		walker:         w,
		artifactOption: opt,
	}, nil
}

// Inspect walks the AppImage's SquashFS filesystem, runs all configured
// analyzers, caches the result and returns an artifact.Reference.
func (a *Artifact) Inspect(ctx context.Context) (artifact.Reference, error) {
	blobInfo, err := a.analyze(ctx)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("analysis error: %w", err)
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("cache key error: %w", err)
	}

	if err = a.cache.PutBlob(ctx, cacheKey, blobInfo); err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to store blob in cache: %w", err)
	}

	return artifact.Reference{
		Name:    a.filePath,
		Type:    types.TypeAppImage,
		ID:      cacheKey,
		BlobIDs: []string{cacheKey},
	}, nil
}

// Clean removes the cached blobs associated with this artifact.
func (a *Artifact) Clean(ref artifact.Reference) error {
	defer a.file.Close() //nolint:errcheck
	return a.cache.DeleteBlobs(context.TODO(), ref.BlobIDs)
}

// analyze walks the SquashFS and runs all analyzers.
func (a *Artifact) analyze(ctx context.Context) (types.BlobInfo, error) {
	eg, egCtx := errgroup.WithContext(ctx)
	limit := semaphore.New(a.artifactOption.Parallel)
	result := analyzer.NewAnalysisResult()

	opts := analyzer.AnalysisOptions{
		Offline:      a.artifactOption.Offline,
		FileChecksum: a.artifactOption.FileChecksum,
	}

	// Prepare filesystem for post-analysis
	composite, err := a.analyzer.PostAnalyzerFS()
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get post analysis filesystem: %w", err)
	}
	defer composite.Cleanup()

	walkErr := a.walker.Walk(a.reader, "/", a.artifactOption.WalkerOption, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err := a.analyzer.AnalyzeFile(egCtx, eg, limit, result, "/", filePath, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", filePath, err)
		}

		analyzerTypes := a.analyzer.RequiredPostAnalyzers(filePath, info)
		if len(analyzerTypes) == 0 {
			return nil
		}

		tmpFilePath, err := composite.CopyFileToTemp(opener, info)
		if err != nil {
			return xerrors.Errorf("failed to copy file to temp: %w", err)
		}
		return composite.CreateLink(analyzerTypes, "", filePath, tmpFilePath)
	})
	if walkErr != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk appimage error: %w", walkErr)
	}

	if err = eg.Wait(); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("analyze error: %w", err)
	}

	if err = a.analyzer.PostAnalyze(ctx, composite, result, opts); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("post analysis error: %w", err)
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
		BuildInfo:       result.BuildInfo,
	}

	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	return blobInfo, nil
}

func (a *Artifact) calcCacheKey(blobInfo types.BlobInfo) (string, error) {
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(blobInfo); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}
	d := digest.NewDigest(digest.SHA256, h)
	cacheKey, err := cache.CalcKey(d.String(), artifactVersion, a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", xerrors.Errorf("cache key calculation error: %w", err)
	}
	return cacheKey, nil
}
