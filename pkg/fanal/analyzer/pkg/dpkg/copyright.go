package dpkg

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&dpkgLicenseAnalyzer{})

	var err error
	licenseClassifier, err = assets.DefaultClassifier()
	if err != nil {
		panic(err)
	}
}

var (
	dpkgLicenseAnalyzerVersion = 1

	licenseClassifier *classifier.Classifier

	commonLicenseReferenceRegexp = regexp.MustCompile(`/?usr/share/common-licenses/([0-9A-Za-z_.+-]+[0-9A-Za-z+])`)
)

// dpkgLicenseAnalyzer parses copyright files and detect licenses
type dpkgLicenseAnalyzer struct{}

// Analyze parses /usr/share/doc/*/copyright files
func (a dpkgLicenseAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	licenses, err := a.parseCopyright(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", input.FilePath, err)
	}

	licensesStr := strings.Join(licenses, ", ")
	if licensesStr == "" {
		licensesStr = "Unknown"
	}

	return &analyzer.AnalysisResult{
		CustomResources: []types.CustomResource{
			{
				Type:     string(types.DpkgLicensePostHandler),
				FilePath: input.FilePath,
				Data:     licensesStr,
			},
		},
	}, nil
}

// parseCopyright parses /usr/share/doc/*/copyright files
func (a dpkgLicenseAnalyzer) parseCopyright(r dio.ReadSeekerAt) ([]string, error) {
	scanner := bufio.NewScanner(r)
	var licenses []string
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "License:"):
			// Machine-readable format
			// cf. https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#:~:text=The%20debian%2Fcopyright%20file%20must,in%20the%20Debian%20Policy%20Manual.
			l := strings.TrimSpace(line[8:])
			if !slices.Contains(licenses, l) {
				licenses = append(licenses, l)
			}
		case strings.Contains(line, "/usr/share/common-licenses/"):
			// Common license pattern
			license := commonLicenseReferenceRegexp.FindStringSubmatch(line)
			if len(license) == 2 && !slices.Contains(licenses, license[1]) {
				licenses = append(licenses, license[1])
			}
		}
	}

	// If licenses are already found, they will be returned.
	if len(licenses) > 0 {
		return licenses, nil
	}

	// Rewind the reader to the beginning of the stream after saving
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("unable to rewind reader: %w", err)
	}

	// Use 'github.com/google/licenseclassifier' to find licenses
	result, err := licenseClassifier.MatchFrom(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to match licenses: %w", err)
	}

	for _, match := range result.Matches {
		if match.Confidence > 0.9 && !slices.Contains(licenses, match.Name) {
			licenses = append(licenses, match.Name)
		}
	}

	return licenses, nil
}

func (a dpkgLicenseAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasPrefix(filePath, "usr/share/doc/") && filepath.Base(filePath) == "copyright"
}

func (a dpkgLicenseAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDpkgLicense
}

func (a dpkgLicenseAnalyzer) Version() int {
	return dpkgLicenseAnalyzerVersion
}
