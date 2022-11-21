package dpkg

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
}

var (
	dpkgLicenseAnalyzerVersion = 1

	commonLicenseReferenceRegexp = regexp.MustCompile(`/?usr/share/common-licenses/([0-9A-Za-z_.+-]+[0-9A-Za-z+])`)
	licenseSplitRegexp           = regexp.MustCompile("(,?[_ ]+or[_ ]+)|(,?[_ ]+and[_ ])|(,[ ]*)")
)

// dpkgLicenseAnalyzer parses copyright files and detect licenses
type dpkgLicenseAnalyzer struct {
	licenseFull bool
}

// Analyze parses /usr/share/doc/*/copyright files
func (a *dpkgLicenseAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	findings, err := a.parseCopyright(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("parse copyright %s: %w", input.FilePath, err)
	}

	// If licenses are not found, fallback to the classifier
	if len(findings) == 0 && a.licenseFull {
		// Rewind the reader to the beginning of the stream after saving
		if _, err = input.Content.Seek(0, io.SeekStart); err != nil {
			return nil, xerrors.Errorf("seek error: %w", err)
		}

		licenseFile, err := licensing.Classify(input.FilePath, input.Content)
		if err != nil {
			return nil, xerrors.Errorf("license classification error: %w", err)
		}
		findings = licenseFile.Findings
	}

	if len(findings) == 0 {
		return nil, nil
	}

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
func (a *dpkgLicenseAnalyzer) parseCopyright(r dio.ReadSeekerAt) ([]types.LicenseFinding, error) {
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
				// Split licenses without considering "and"/"or"
				// examples:
				// 'GPL-1+,GPL-2' => {"GPL-1", "GPL-2"}
				// 'GPL-1+ or Artistic or Artistic-dist' => {"GPL-1", "Artistic", "Artistic-dist"}
				// 'LGPLv3+_or_GPLv2+' => {"LGPLv3", "GPLv2"}
				// 'BSD-3-CLAUSE and GPL-2' => {"BSD-3-CLAUSE", "GPL-2"}
				// 'GPL-1+ or Artistic, and BSD-4-clause-POWERDOG' => {"GPL-1+", "Artistic", "BSD-4-clause-POWERDOG"}
				for _, lic := range licenseSplitRegexp.Split(l, -1) {
					lic = licensing.Normalize(lic)
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

	return lo.Map(licenses, func(license string, _ int) types.LicenseFinding {
		return types.LicenseFinding{Name: license}
	}), nil

}

func (a *dpkgLicenseAnalyzer) Init(opt analyzer.AnalyzerOptions) error {
	a.licenseFull = opt.LicenseScannerOption.Full
	return nil
}

func (a *dpkgLicenseAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasPrefix(filePath, "usr/share/doc/") && filepath.Base(filePath) == "copyright"
}

func (a *dpkgLicenseAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDpkgLicense
}

func (a *dpkgLicenseAnalyzer) Version() int {
	return dpkgLicenseAnalyzerVersion
}
