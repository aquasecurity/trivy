package licensing

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
)

const version = 1

var (
	skipDirs = []string{
		"node_modules/",  // node scan will pick these up
		"usr/share/doc/", // dpkg will pick these up

		// Some heuristic exclusion
		"usr/lib",
		"usr/local/include",
		"usr/include",
		"usr/lib/python",
		"usr/local/go",
		"opt/yarn",
		"usr/lib/gems",
		"usr/src/wordpress",
	}

	acceptedExtensions = []string{
		".asp", ".aspx", ".bas", ".bat", ".b", ".c", ".cue", ".cgi", ".cs", ".css", ".fish", ".html", ".h", ".ini",
		".java", ".js", ".jsx", ".markdown", ".md", ".py", ".php", ".pl", ".r", ".rb", ".sh", ".sql", ".ts",
		".tsx", ".txt", ".vue", ".zsh",
	}

	acceptedFileNames = []string{
		"license", "licence", "copyright", // nolint: misspell
	}
)

func init() {
	analyzer.RegisterAnalyzer(licenseFileAnalyzer{})
}

// licenseFileAnalyzer is an analyzer for file headers and license files
type licenseFileAnalyzer struct{}

func (a licenseFileAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	log.Logger.Debugf("License scanning: %s", input.FilePath)

	// need files to be text based, readable files
	readable, err := isHumanReadable(input.Content, input.Info.Size())
	if err != nil || !readable {
		return nil, nil
	}

	content, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("read error %s: %w", input.FilePath, err)
	}
	content = bytes.Replace(content, []byte("\r"), []byte(""), -1)

	filePath := input.FilePath
	// Files extracted from the image have an empty input.Dir.
	// Also, paths to these files do not have "/" prefix.
	// We need to add a "/" prefix to properly filter paths from the config file.
	if input.Dir == "" { // add leading path separator for files extracted from image
		filePath = fmt.Sprintf("%c%s", os.PathSeparator, filePath)
	}

	lf, err := licensing.FullClassify(filePath, content)
	if err != nil {
		return nil, xerrors.Errorf("license classification error: %w", err)
	} else if len(lf.Findings) == 0 {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		Licenses: []types.LicenseFile{lf},
	}, nil
}

func (a licenseFileAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	for _, skipDir := range skipDirs {
		if strings.Contains(filePath, skipDir) {
			return false
		}
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	if slices.Contains(acceptedExtensions, ext) {
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

func (a licenseFileAnalyzer) Type() analyzer.Type {
	return analyzer.TypeLicenseFile
}

func (a licenseFileAnalyzer) Version() int {
	return version
}
