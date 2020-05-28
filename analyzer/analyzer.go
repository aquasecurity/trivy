package analyzer

import (
	"os"
	"strings"
	"sync"

	aos "github.com/aquasecurity/fanal/analyzer/os"

	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
)

var (
	analyzers       []analyzer
	configAnalyzers []configAnalyzer

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("no packages detected")
)

type AnalyzeReturn struct {
	OS        types.OS
	Packages  []types.Package
	Libraries []godeptypes.Library
}

func (r AnalyzeReturn) ConvertToResult(analyzerType, filePath string) *AnalysisResult {
	result := new(AnalysisResult)
	if r.OS != (types.OS{}) {
		result.OS = &r.OS
	}

	if len(r.Packages) > 0 {
		result.PackageInfos = []types.PackageInfo{{
			FilePath: filePath,
			Packages: r.Packages,
		}}
	}

	if len(r.Libraries) > 0 {
		var libs []types.LibraryInfo
		for _, lib := range r.Libraries {
			libs = append(libs, types.LibraryInfo{
				Library: lib,
			})
		}
		result.Applications = []types.Application{{
			Type:      analyzerType,
			FilePath:  filePath,
			Libraries: libs,
		}}
	}
	return result
}

type analyzer interface {
	Name() string
	Analyze(content []byte) (AnalyzeReturn, error)
	Required(filePath string, info os.FileInfo) bool
}

func RegisterAnalyzer(analyzer analyzer) {
	analyzers = append(analyzers, analyzer)
}

type configAnalyzer interface {
	Analyze(targetOS types.OS, content []byte) ([]types.Package, error)
	Required(osFound types.OS) bool
}

func RegisterConfigAnalyzer(analyzer configAnalyzer) {
	configAnalyzers = append(configAnalyzers, analyzer)
}

type Opener func() ([]byte, error)

type AnalysisResult struct {
	m            sync.Mutex
	OS           *types.OS
	PackageInfos []types.PackageInfo
	Applications []types.Application
}

func (r *AnalysisResult) isEmpty() bool {
	return r.OS == nil && len(r.PackageInfos) == 0 && len(r.Applications) == 0
}

func (r *AnalysisResult) Merge(new *AnalysisResult) {
	if new == nil || new.isEmpty() {
		return
	}

	// this struct is accessed by multiple goroutines
	r.m.Lock()
	defer r.m.Unlock()

	if new.OS != nil {
		// OLE also has /etc/redhat-release and it detects OLE as RHEL by mistake.
		// In that case, OS must be overwritten with the content of /etc/oracle-release.
		// There is the same problem between Debian and Ubuntu.
		if r.OS == nil || r.OS.Family == aos.RedHat || r.OS.Family == aos.Debian {
			r.OS = new.OS
		}
	}

	if len(new.PackageInfos) > 0 {
		r.PackageInfos = append(r.PackageInfos, new.PackageInfos...)
	}

	if len(new.Applications) > 0 {
		r.Applications = append(r.Applications, new.Applications...)
	}
}

func AnalyzeFile(filePath string, info os.FileInfo, opener Opener) (*AnalysisResult, error) {
	result := new(AnalysisResult)
	for _, analyzer := range analyzers {
		// filepath extracted from tar file doesn't have the prefix "/"
		if !analyzer.Required(strings.TrimLeft(filePath, "/"), info) {
			continue
		}
		b, err := opener()
		if err != nil {
			return nil, xerrors.Errorf("unable to open a file (%s): %w", filePath, err)
		}

		ret, err := analyzer.Analyze(b)
		if err != nil {
			continue
		}
		result.Merge(ret.ConvertToResult(analyzer.Name(), filePath))
	}
	return result, nil
}

func AnalyzeConfig(targetOS types.OS, configBlob []byte) []types.Package {
	for _, analyzer := range configAnalyzers {
		if !analyzer.Required(targetOS) {
			continue
		}

		pkgs, err := analyzer.Analyze(targetOS, configBlob)
		if err != nil {
			continue
		}
		return pkgs
	}
	return nil
}

func CheckPackage(pkg *types.Package) bool {
	return pkg.Name != "" && pkg.Version != ""
}
