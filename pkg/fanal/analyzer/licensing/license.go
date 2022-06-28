package licensing

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/licensing"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
)

const version = 1

var skipDirs = []string{
	"node_modules/",
	"usr/share/doc/",
}

var includedExts = []string{
	".asp", ".aspx", ".bas", ".bat", ".b", ".c", ".cgi", ".cs", ".css", ".fish", ".html", ".h", ".ini",
	".java", ".js", ".jsx", ".js.map", ".markdown", ".md", ".py", ".php", ".pl", ".r", ".rb", ".sh", ".sql", ".ts",
	".tsx", ".ts.map", ".txt", ".zsh",
}

var acceptedFileNames = []string{
	"license", "licence", "copyright",
}

type ScannerOption struct {
	IgnoredLicenses []string
	RiskThreshold   int
}

// LicenseAnalyzer is an analyzer for licenses
type LicenseAnalyzer struct {
	scanner licensing.Scanner
}

func RegisterLicenseScanner(opt ScannerOption) error {
	a, err := newLicenseScanner(opt)
	if err != nil {
		return xerrors.Errorf("license scanner init error: %w", err)
	}
	analyzer.RegisterAnalyzer(a)
	return nil
}

func newLicenseScanner(opt ScannerOption) (LicenseAnalyzer, error) {
	s, err := licensing.NewScanner(opt.RiskThreshold, opt.IgnoredLicenses)
	if err != nil {
		return LicenseAnalyzer{}, xerrors.Errorf("license scanner error: %w", err)
	}
	return LicenseAnalyzer{
		scanner: s,
	}, nil
}

func (a LicenseAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {

	// need files to be text based, readable files
	readable, err := isHumanReadable(input.Content, input.Info.Size())
	if err != nil || !readable {
		return nil, nil
	}

	content, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("read error %s: %w", input.FilePath, err)
	}

	filePath := input.FilePath
	// Files extracted from the image have an empty input.Dir.
	// Also, paths to these files do not have "/" prefix.
	// We need to add a "/" prefix to properly filter paths from the config file.
	if input.Dir == "" { // add leading `/` for files extracted from image
		filePath = fmt.Sprintf("/%s", filePath)
	}

	lf := a.scanner.Scan(licensing.ScanArgs{
		FilePath: filePath,
		Content:  content,
	})
	if len(lf.Findings) == 0 {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		Licenses: []types.LicenseFile{lf},
	}, nil
}

func (a LicenseAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	for _, skipDir := range skipDirs {
		if strings.HasPrefix(filePath, skipDir) {
			return false
		}
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	if slices.Contains(includedExts, ext) {
		return true
	}

	baseName := strings.ToLower(filepath.Base(filePath))
	return slices.Contains(acceptedFileNames, baseName)
}

func isHumanReadable(content dio.ReadSeekerAt, fileSize int64) (bool, error) {
	headSize := int(math.Min(float64(fileSize), 300))
	head := make([]byte, headSize)
	if _, err := content.Read(head); err != nil {
		return false, err
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return false, err
	}

	// cf. https://github.com/file/file/blob/f2a6e7cb7db9b5fd86100403df6b2f830c7f22ba/src/encoding.c#L151-L228
	for _, b := range head {
		if b < 7 || b == 11 || (13 < b && b < 27) || (27 < b && b < 0x20) || b == 0x7f {
			return false, nil
		}
	}

	return true, nil
}

func (a LicenseAnalyzer) Type() analyzer.Type {
	return analyzer.TypeLicense
}

func (a LicenseAnalyzer) Version() int {
	return version
}
