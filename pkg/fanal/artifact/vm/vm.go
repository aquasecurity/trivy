package vm

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/xerrors"

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

type Storage struct {
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager
	walker         walker.VM

	artifactOption artifact.Option
}

func (a *Storage) Analyze(ctx context.Context, r *io.SectionReader) (types.BlobInfo, error) {
	var wg sync.WaitGroup
	limit := semaphore.New(a.artifactOption.Slow)
	result := analyzer.NewAnalysisResult()

	// TODO: Always walk from the root directory. Consider whether there is a need to be able to set optional
	err := a.walker.Walk(r, "/", func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		opts := analyzer.AnalysisOptions{Offline: a.artifactOption.Offline}
		path := strings.TrimPrefix(filePath, "/")
		if err := a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "/", path, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", path, err)
		}
		return nil
	})

	// Wait for all the goroutine to finish.
	wg.Wait()

	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk vm error: %w", err)
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
		return types.BlobInfo{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	return blobInfo, nil
}

func NewArtifact(target string, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler init error: %w", err)
	}
	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		Group:                opt.AnalyzerGroup,
		FilePatterns:         opt.FilePatterns,
		DisabledAnalyzers:    opt.DisabledAnalyzers,
		SecretScannerOption:  opt.SecretScannerOption,
		LicenseScannerOption: opt.LicenseScannerOption,
	})
	if err != nil {
		return nil, xerrors.Errorf("analyzer group error: %w", err)
	}

	storage := Storage{
		cache:          c,
		analyzer:       a,
		handlerManager: handlerManager,
		walker:         walker.NewVM(opt.SkipFiles, opt.SkipDirs, opt.OnlyDirs, opt.Slow),
		artifactOption: opt,
	}

	targetType := detectType(target)
	switch targetType {
	case TypeAMI:
		target = strings.TrimPrefix(target, TypeAMI.Prefix())
		return newAMI(target, storage, opt.AWSRegion)
	case TypeEBS:
		target = strings.TrimPrefix(target, TypeEBS.Prefix())
		e, err := newEBS(target, storage, opt.AWSRegion)
		if err != nil {
			return nil, xerrors.Errorf("new EBS error: %w", err)
		}
		return e, nil
	case TypeFile:
		target = strings.TrimPrefix(target, TypeFile.Prefix())
		return newFile(target, storage)
	}
	return nil, xerrors.Errorf("unsupported format")
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
