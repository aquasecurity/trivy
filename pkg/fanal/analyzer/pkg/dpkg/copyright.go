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
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
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
		return nil, xerrors.Errorf("parse copyright %s: %w", input.FilePath, err)
	} else if len(licenses) == 0 {
		return nil, nil
	}

	findings := lo.Map(licenses, func(license string, _ int) types.LicenseFinding {
		return types.LicenseFinding{Name: license}
	})

	// e.g. "usr/share/doc/zlib1g/copyright" => "zlib1g"
	pkgName := strings.Split(input.FilePath, "/")[3]

	return &analyzer.AnalysisResult{
		Licenses: []types.LicenseFile{
			{
				Type:     types.LicenseTypeDpkg,
				FilePath: input.FilePath,
				Findings: findings,
				PkgName:  pkgName,
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
			if len(l) > 0 {
				lics := splitLicenses(l) // splitting lines containing "or" or "and"
				for _, lic := range lics {
					if !slices.Contains(licenses, lic) {
						licenses = append(licenses, lic)
					}
				}
			}
		case strings.Contains(line, "/usr/share/common-licenses/"):
			// Common license pattern
			license := commonLicenseReferenceRegexp.FindStringSubmatch(line)
			if len(license) == 2 {
				l := licensing.Normalize(license[1])
				if !slices.Contains(licenses, l) {
					licenses = append(licenses, l)
				}
			}
		}
	}

	// If licenses are already found, they will be returned.
	if len(licenses) > 0 {
		return licenses, nil
	}

	// Rewind the reader to the beginning of the stream after saving
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("seek error: %w", err)
	}

	// Use 'github.com/google/licenseclassifier' to find licenses
	result, err := licenseClassifier.MatchFrom(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to match licenses: %w", err)
	}

	for _, match := range result.Matches {
		if match.Confidence > 0.9 {
			l := licensing.Normalize(match.Name)
			if !slices.Contains(licenses, l) {
				licenses = append(licenses, l)
			}
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

// examples:
// 'GPL-1+,GPL-2', 'GPL-1+, GPL-2'.
// 'GPL-1+ or Artistic or Artistic-dist', 'LGPLv3+_or_GPLv2+', 'LGPL-2.1+    or     BSD-3-clause'
// 'BSD-3-CLAUSE and GPL-2', 'GPL-1+ or Artistic, and BSD-4-clause-POWERDOG'
// splitLicenses returns a list of licenses if the string contains multiple licenses
func splitLicenses(line string) []string {
	re := regexp.MustCompile("(,?[_ ]+or[_ ]+)|(,?[_ ]+and[_ ])|(,[ ]*)")
	licenses := re.Split(line, -1)

	for i, license := range licenses {
		licenses[i] = licensing.Normalize(license)
	}
	return licenses
}
