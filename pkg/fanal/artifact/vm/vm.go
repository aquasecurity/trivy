package vm

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/google/wire"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/semaphore"
)

type Type string

func (t Type) Prefix() string {
	return string(t) + ":"
}

const (
	TypeAMI  Type = "ami"
	TypeEBS  Type = "ebs"
	TypeFile Type = "file"
)

var (
	ArtifactSet = wire.NewSet(
		walker.NewVM,
		wire.Bind(new(Walker), new(*walker.VM)),
		NewArtifact,
	)

	_ Walker = (*walker.VM)(nil)
)

type Walker interface {
	Walk(*io.SectionReader, string, walker.Option, walker.WalkFunc) error
}

func NewArtifact(target string, c cache.ArtifactCache, w Walker, opt artifact.Option) (artifact.Artifact, error) {
	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, fmt.Errorf("handler init error: %w", err)
	}
	a, err := analyzer.NewAnalyzerGroup(opt.AnalyzerOptions())
	if err != nil {
		return nil, fmt.Errorf("analyzer group error: %w", err)
	}

	storage := Storage{
		cache:          c,
		analyzer:       a,
		handlerManager: handlerManager,
		walker:         w,
		artifactOption: opt,
	}

	targetType := detectType(target)
	switch targetType {
	case TypeAMI:
		target = strings.TrimPrefix(target, TypeAMI.Prefix())
		return newAMI(target, storage, opt.AWSRegion, opt.AWSEndpoint)
	case TypeEBS:
		target = strings.TrimPrefix(target, TypeEBS.Prefix())
		e, err := newEBS(target, storage, opt.AWSRegion, opt.AWSEndpoint)
		if err != nil {
			return nil, fmt.Errorf("new EBS error: %w", err)
		}
		return e, nil
	case TypeFile:
		target = strings.TrimPrefix(target, TypeFile.Prefix())
		return newFile(target, storage)
	}
	return nil, fmt.Errorf("unsupported format")
}

type Storage struct {
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager
	walker         Walker

	artifactOption artifact.Option
}

func (a *Storage) Analyze(ctx context.Context, r *io.SectionReader) (types.BlobInfo, error) {
	var wg sync.WaitGroup
	limit := semaphore.New(a.artifactOption.Parallel)
	result := analyzer.NewAnalysisResult()

	opts := analyzer.AnalysisOptions{
		Offline:      a.artifactOption.Offline,
		FileChecksum: a.artifactOption.FileChecksum,
	}

	// Prepare filesystem for post analysis
	composite, err := a.analyzer.PostAnalyzerFS()
	if err != nil {
		return types.BlobInfo{}, fmt.Errorf("unable to get post analysis filesystem: %w", err)
	}
	defer composite.Cleanup()

	// TODO: Always walk from the root directory. Consider whether there is a need to be able to set optional
	err = a.walker.Walk(r, "/", a.artifactOption.WalkerOption, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		path := strings.TrimPrefix(filePath, "/")
		if err := a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "/", path, info, opener, nil, opts); err != nil {
			return fmt.Errorf("analyze file (%s): %w", path, err)
		}

		// Skip post analysis if the file is not required
		analyzerTypes := a.analyzer.RequiredPostAnalyzers(path, info)
		if len(analyzerTypes) == 0 {
			return nil
		}

		// Build filesystem for post analysis
		tmpFilePath, err := composite.CopyFileToTemp(opener, info)
		if err != nil {
			return fmt.Errorf("failed to copy file to temp: %w", err)
		}

		if err = composite.CreateLink(analyzerTypes, "", path, tmpFilePath); err != nil {
			return fmt.Errorf("failed to write a file: %w", err)
		}

		return nil
	})

	// Wait for all the goroutine to finish.
	wg.Wait()

	if err != nil {
		return types.BlobInfo{}, fmt.Errorf("walk vm error: %w", err)
	}

	// Post-analysis
	if err = a.analyzer.PostAnalyze(ctx, composite, result, opts); err != nil {
		return types.BlobInfo{}, fmt.Errorf("post analysis error: %w", err)
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
		return types.BlobInfo{}, fmt.Errorf("failed to call hooks: %w", err)
	}

	return blobInfo, nil
}

func detectType(target string) Type {
	switch {
	case strings.HasPrefix(target, TypeAMI.Prefix()):
		return TypeAMI
	case strings.HasPrefix(target, TypeEBS.Prefix()):
		return TypeEBS
	case strings.HasPrefix(target, TypeFile.Prefix()):
		return TypeFile
	default:
		return TypeFile
	}
}
