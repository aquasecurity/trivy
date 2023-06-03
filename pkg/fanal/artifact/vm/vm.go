package vm

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/mapfs"
	"github.com/aquasecurity/trivy/pkg/semaphore"
	"github.com/aquasecurity/trivy/pkg/syncx"
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

	opts := analyzer.AnalysisOptions{
		Offline:      a.artifactOption.Offline,
		FileChecksum: a.artifactOption.FileChecksum,
	}
	// Prepare filesystem for post analysis
	files := new(syncx.Map[analyzer.Type, *mapfs.FS])

	tmpDir, err := os.MkdirTemp("", "vm-partitions-*")
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("mkdir temp error: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// TODO: Always walk from the root directory. Consider whether there is a need to be able to set optional
	err = a.walker.Walk(r, "/", func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		path := strings.TrimPrefix(filePath, "/")
		if err := a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "/", path, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", path, err)
		}

		// Build filesystem for post analysis
		if err := a.buildFS(tmpDir, path, info, opener, files); err != nil {
			return xerrors.Errorf("failed to build filesystem: %w", err)
		}

		return nil
	})

	// Wait for all the goroutine to finish.
	wg.Wait()

	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk vm error: %w", err)
	}

	// Post-analysis
	if err = a.analyzer.PostAnalyze(ctx, files, result, opts); err != nil {
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
		MisconfScannerOption: opt.MisconfScannerOption,
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
		walker:         walker.NewVM(opt.SkipFiles, opt.SkipDirs, opt.Slow),
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

// buildFS creates filesystem for post analysis
func (a Storage) buildFS(tmpDir, filePath string, info os.FileInfo, opener analyzer.Opener,
	files *syncx.Map[analyzer.Type, *mapfs.FS]) error {
	// Get all post-analyzers that want to analyze the file
	atypes := a.analyzer.RequiredPostAnalyzers(filePath, info)
	if len(atypes) == 0 {
		return nil
	}

	// Create a temporary file to which the file in the filesystem of the vm will be copied
	// so that all the files will not be loaded into memory
	f, err := os.CreateTemp(tmpDir, "vm-file-*")
	if err != nil {
		return xerrors.Errorf("create temp error: %w", err)
	}
	defer f.Close()

	// Open a file in the filesystem of the vm
	r, err := opener()
	if err != nil {
		return xerrors.Errorf("file open error: %w", err)
	}
	defer r.Close()

	// Copy file content into the temporary file
	if _, err = io.Copy(f, r); err != nil {
		return xerrors.Errorf("copy error: %w", err)
	}

	if err = os.Chmod(f.Name(), info.Mode()); err != nil {
		return xerrors.Errorf("chmod error: %w", err)
	}

	// Create fs.FS for each post-analyzer that wants to analyze the current file
	for _, at := range atypes {
		fsys, _ := files.LoadOrStore(at, mapfs.New())
		if dir := filepath.Dir(filePath); dir != "." {
			if err := fsys.MkdirAll(dir, os.ModePerm); err != nil && !errors.Is(err, fs.ErrExist) {
				return xerrors.Errorf("mapfs mkdir error: %w", err)
			}
		}
		err = fsys.WriteFile(filePath, f.Name())
		if err != nil {
			return xerrors.Errorf("mapfs write error: %w", err)
		}
	}
	return nil
}
