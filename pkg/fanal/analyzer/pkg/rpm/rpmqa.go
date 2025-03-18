package rpm

import (
	"bufio"
	"context"
	"os"
	"slices"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterAnalyzer(&rpmqaPkgAnalyzer{})
}

const versionRpmqa = 1

var (
	// For CBL-Mariner Distroless
	requiredRpmqaFiles = []string{"var/lib/rpmmanifest/container-manifest-2"}
)

// rpmqaPkgAnalyzer parses the output of
// "rpm -qa --qf %{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t(none)\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}".
type rpmqaPkgAnalyzer struct{}

func (a rpmqaPkgAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	pkgs, err := a.parseRpmqaManifest(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse rpmqa manifest: %w", err)
	}
	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: pkgs,
			},
		},
	}, nil
}

func (a rpmqaPkgAnalyzer) parseRpmqaManifest(r xio.ReadSeekerAt) ([]types.Package, error) {
	var pkgs []types.Package
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		var name, ver, rel, sourceRpm, arch string
		// %{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t(none)\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}
		s := strings.Split(line, "\t")
		if len(s) != 10 {
			return nil, xerrors.Errorf("failed to parse a line (%s)", line)
		}
		name = s[0]
		arch = s[7]
		sourceRpm = s[9]
		if verRel := strings.Split(s[1], "-"); len(verRel) == 2 {
			ver = verRel[0]
			rel = verRel[1]
		} else {
			return nil, xerrors.Errorf("failed to split a version (%s)", s[1])
		}
		srcName, srcVer, srcRel, err := splitFileName(sourceRpm)
		if err != nil {
			return nil, xerrors.Errorf("failed to split source rpm: %w", err)
		}
		pkgs = append(pkgs, types.Package{
			Name:       name,
			Version:    ver,
			Release:    rel,
			Arch:       arch,
			SrcName:    srcName,
			SrcVersion: srcVer,
			SrcRelease: srcRel,
		})
	}
	return pkgs, nil
}

func (a rpmqaPkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredRpmqaFiles, filePath)
}

func (a rpmqaPkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRpmqa
}

func (a rpmqaPkgAnalyzer) Version() int {
	return versionRpmqa
}

func (a rpmqaPkgAnalyzer) StaticPaths() []string {
	return requiredRpmqaFiles
}
