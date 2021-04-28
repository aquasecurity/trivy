package analyzer

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	aos "github.com/aquasecurity/fanal/analyzer/os"
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

type AnalysisTarget struct {
	FilePath string
	Content  []byte
}

type analyzer interface {
	Type() Type
	Version() int
	Analyze(input AnalysisTarget) (*AnalysisResult, error)
	Required(filePath string, info os.FileInfo) bool
}

type configAnalyzer interface {
	Type() Type
	Version() int
	Analyze(targetOS types.OS, content []byte) ([]types.Package, error)
	Required(osFound types.OS) bool
}

func RegisterAnalyzer(analyzer analyzer) {
	analyzers = append(analyzers, analyzer)
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
	Configs      []types.Config
}

func (r *AnalysisResult) isEmpty() bool {
	return r.OS == nil && len(r.PackageInfos) == 0 && len(r.Applications) == 0 && len(r.Configs) == 0
}

func (r *AnalysisResult) Sort() {
	sort.Slice(r.PackageInfos, func(i, j int) bool {
		return r.PackageInfos[i].FilePath < r.PackageInfos[j].FilePath
	})

	sort.Slice(r.Applications, func(i, j int) bool {
		return r.Applications[i].FilePath < r.Applications[j].FilePath
	})

	sort.Slice(r.Configs, func(i, j int) bool {
		return r.Configs[i].FilePath < r.Configs[j].FilePath
	})
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

	if len(new.Configs) > 0 {
		r.Configs = append(r.Configs, new.Configs...)
	}
}

type Analyzer struct {
	drivers       []analyzer
	configDrivers []configAnalyzer
	disabled      []Type
}

func NewAnalyzer(disabledAnalyzers []Type) Analyzer {
	var drivers []analyzer
	for _, a := range analyzers {
		if isDisabled(a.Type(), disabledAnalyzers) {
			continue
		}
		drivers = append(drivers, a)
	}

	var configDrivers []configAnalyzer
	for _, a := range configAnalyzers {
		if isDisabled(a.Type(), disabledAnalyzers) {
			continue
		}
		configDrivers = append(configDrivers, a)
	}

	return Analyzer{
		drivers:       drivers,
		configDrivers: configDrivers,
		disabled:      disabledAnalyzers,
	}
}

// AnalyzerVersions returns analyzer version identifier used for cache suffixes.
// e.g. alpine: 1, amazon: 3, debian: 2 => 132
// When the amazon analyzer is disabled => 102
func (a Analyzer) AnalyzerVersions() string {
	// Sort analyzers for the consistent version identifier
	sorted := make([]analyzer, len(analyzers))
	copy(sorted, analyzers)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Type() < sorted[j].Type()
	})

	var versions string
	for _, s := range sorted {
		if isDisabled(s.Type(), a.disabled) {
			versions += "0"
			continue
		}
		versions += fmt.Sprint(s.Version())
	}
	return versions
}

// ImageConfigAnalyzerVersions returns analyzer version identifier used for cache suffixes.
func (a Analyzer) ImageConfigAnalyzerVersions() string {
	// Sort image config analyzers for the consistent version identifier.
	sorted := make([]configAnalyzer, len(configAnalyzers))
	copy(sorted, configAnalyzers)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Type() < sorted[j].Type()
	})

	var versions string
	for _, s := range sorted {
		if isDisabled(s.Type(), a.disabled) {
			versions += "0"
			continue
		}
		versions += fmt.Sprint(s.Version())
	}
	return versions
}

func (a Analyzer) AnalyzeFile(ctx context.Context, wg *sync.WaitGroup, limit *semaphore.Weighted, result *AnalysisResult,
	filePath string, info os.FileInfo, opener Opener) error {
	for _, d := range a.drivers {
		// filepath extracted from tar file doesn't have the prefix "/"
		if !d.Required(strings.TrimLeft(filePath, "/"), info) {
			continue
		}
		b, err := opener()
		if err != nil {
			return xerrors.Errorf("unable to open a file (%s): %w", filePath, err)
		}

		if err = limit.Acquire(ctx, 1); err != nil {
			return xerrors.Errorf("semaphore acquire: %w", err)
		}
		wg.Add(1)

		go func(a analyzer, target AnalysisTarget) {
			defer limit.Release(1)
			defer wg.Done()

			ret, err := a.Analyze(target)
			if err != nil {
				return
			}
			result.Merge(ret)
		}(d, AnalysisTarget{FilePath: filePath, Content: b})
	}
	return nil
}

func (a Analyzer) AnalyzeImageConfig(targetOS types.OS, configBlob []byte) []types.Package {
	for _, d := range a.configDrivers {
		if !d.Required(targetOS) {
			continue
		}

		pkgs, err := d.Analyze(targetOS, configBlob)
		if err != nil {
			continue
		}
		return pkgs
	}
	return nil
}

func isDisabled(t Type, disabled []Type) bool {
	for _, d := range disabled {
		if t == d {
			return true
		}
	}
	return false
}

func CheckPackage(pkg *types.Package) bool {
	return pkg.Name != "" && pkg.Version != ""
}
