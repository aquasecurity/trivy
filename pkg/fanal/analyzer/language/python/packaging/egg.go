package packaging

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePythonPkgEgg, newEggAnalyzer)
}

const (
	eggAnalyzerVersion = 1
	eggExt             = ".egg"
)

func newEggAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &eggAnalyzer{
		logger:    log.WithPrefix("python"),
		pkgParser: packaging.NewParser(),
	}, nil
}

type eggAnalyzer struct {
	logger    *log.Logger
	pkgParser language.Parser
}

// PostAnalyze analyzes egg archive files
func (a eggAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return a.Required(path, nil) || slices.Contains(input.FilePathsMatchedFromPatterns, path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		rsa, ok := r.(xio.ReadSeekerAt)
		if !ok {
			return xerrors.New("invalid reader")
		}

		// .egg file is zip format and PKG-INFO needs to be extracted from the zip file.
		info, err := d.Info()
		if err != nil {
			return xerrors.Errorf("egg file error: %w", err)
		}
		pkginfoInZip, err := a.analyzeEggZip(rsa, info.Size())
		if err != nil {
			return xerrors.Errorf("egg analysis error: %w", err)
		}

		// Egg archive may not contain required files, then we will get nil. Skip this archives
		if pkginfoInZip == nil {
			return nil
		}

		app, err := language.ParsePackage(types.PythonPkg, path, pkginfoInZip, a.pkgParser, input.Options.FileChecksum)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		apps = append(apps, *app)
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("python package walk error: %w", err)
	}
	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a eggAnalyzer) analyzeEggZip(r xio.ReadSeekerAt, size int64) (xio.ReadSeekerAt, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, xerrors.Errorf("zip reader error: %w", err)
	}

	found, ok := lo.Find(zr.File, func(f *zip.File) bool {
		return isEggFile(f.Name)
	})
	if !ok {
		return nil, nil
	}
	return a.open(found)
}

// open reads the file content in the zip archive to make it seekable.
func (a eggAnalyzer) open(file *zip.File) (xio.ReadSeekerAt, error) {
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, xerrors.Errorf("file %s open error: %w", file.Name, err)
	}

	return bytes.NewReader(b), nil
}

func (a eggAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Ext(filePath) == eggExt
}

func (a eggAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkgEgg
}

func (a eggAnalyzer) Version() int {
	return eggAnalyzerVersion
}
