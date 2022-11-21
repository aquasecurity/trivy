package analyzer

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	analyzers       = map[Type]analyzer{}
	configAnalyzers = map[Type]configAnalyzer{}

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("no packages detected")
)

//////////////////////
// Analyzer options //
//////////////////////

// AnalyzerOptions is used to initialize analyzers
type AnalyzerOptions struct {
	Group                Group
	FilePatterns         []string
	DisabledAnalyzers    []Type
	SecretScannerOption  SecretScannerOption
	LicenseScannerOption LicenseScannerOption
}

type SecretScannerOption struct {
	ConfigPath string
}

type LicenseScannerOption struct {
	// Use license classifier to get better results though the classification is expensive.
	Full bool
}

////////////////
// Interfaces //
////////////////

// Initializer represents analyzers that need to take parameters from users
type Initializer interface {
	Init(AnalyzerOptions) error
}

type analyzer interface {
	Type() Type
	Version() int
	Analyze(ctx context.Context, input AnalysisInput) (*AnalysisResult, error)
	Required(filePath string, info os.FileInfo) bool
}

// configAnalyzer defines an interface for container image config analyzer
type configAnalyzer interface {
	Type() Type
	Version() int
	Analyze(input ConfigAnalysisInput) (*AnalysisResult, error)
	Required(osFound types.OS) bool
}

////////////////////
// Analyzer group //
////////////////////

type Group string

const GroupBuiltin Group = "builtin"

func RegisterAnalyzer(analyzer analyzer) {
	analyzers[analyzer.Type()] = analyzer
}

// DeregisterAnalyzer is mainly for testing
func DeregisterAnalyzer(t Type) {
	delete(analyzers, t)
}

func RegisterConfigAnalyzer(analyzer configAnalyzer) {
	configAnalyzers[analyzer.Type()] = analyzer
}

// DeregisterConfigAnalyzer is mainly for testing
func DeregisterConfigAnalyzer(t Type) {
	delete(configAnalyzers, t)
}

// CustomGroup returns a group name for custom analyzers
// This is mainly intended to be used in Aqua products.
type CustomGroup interface {
	Group() Group
}

type Opener func() (dio.ReadSeekCloserAt, error)

type AnalyzerGroup struct {
	analyzers       []analyzer
	configAnalyzers []configAnalyzer
	filePatterns    map[Type][]*regexp.Regexp
}

///////////////////////////
// Analyzer input/output //
///////////////////////////

type AnalysisInput struct {
	Dir      string
	FilePath string
	Info     os.FileInfo
	Content  dio.ReadSeekerAt

	Options AnalysisOptions
}

type AnalysisOptions struct {
	Offline bool
}

type AnalysisResult struct {
	m                    sync.Mutex
	OS                   types.OS
	Repository           *types.Repository
	PackageInfos         []types.PackageInfo
	Applications         []types.Application
	Secrets              []types.Secret
	Licenses             []types.LicenseFile
	SystemInstalledFiles map[string][]string // A map of files installed by OS package manager indexed by package

	// Files holds necessary file contents for the respective post-handler
	Files map[types.HandlerType][]types.File

	// Digests contains SHA-256 digests of unpackaged files
	// used to search for SBOM attestation.
	Digests map[string]string

	// For Red Hat
	BuildInfo *types.BuildInfo

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []types.CustomResource
}

type ConfigAnalysisInput struct {
	OS     types.OS
	Config *v1.ConfigFile
}

func NewAnalysisResult() *AnalysisResult {
	result := new(AnalysisResult)
	result.Files = map[types.HandlerType][]types.File{}
	result.SystemInstalledFiles = map[string][]string{}
	return result
}

func (r *AnalysisResult) isEmpty() bool {
	return lo.IsEmpty(r.OS) && r.Repository == nil && len(r.PackageInfos) == 0 && len(r.Applications) == 0 &&
		len(r.Secrets) == 0 && len(r.Licenses) == 0 && len(r.SystemInstalledFiles) == 0 &&
		r.BuildInfo == nil && len(r.Files) == 0 && len(r.Digests) == 0 && len(r.CustomResources) == 0
}

func (r *AnalysisResult) Sort() {
	// OS packages
	sort.Slice(r.PackageInfos, func(i, j int) bool {
		return r.PackageInfos[i].FilePath < r.PackageInfos[j].FilePath
	})

	for _, pi := range r.PackageInfos {
		sort.Sort(pi.Packages)
	}

	// Language-specific packages
	sort.Slice(r.Applications, func(i, j int) bool {
		return r.Applications[i].FilePath < r.Applications[j].FilePath
	})

	for _, app := range r.Applications {
		sort.Slice(app.Libraries, func(i, j int) bool {
			if app.Libraries[i].Name != app.Libraries[j].Name {
				return app.Libraries[i].Name < app.Libraries[j].Name
			}
			return app.Libraries[i].Version < app.Libraries[j].Version
		})
	}

	// Custom resources
	sort.Slice(r.CustomResources, func(i, j int) bool {
		return r.CustomResources[i].FilePath < r.CustomResources[j].FilePath
	})

	for _, files := range r.Files {
		sort.Slice(files, func(i, j int) bool {
			return files[i].Path < files[j].Path
		})
	}

	// Secrets
	sort.Slice(r.Secrets, func(i, j int) bool {
		return r.Secrets[i].FilePath < r.Secrets[j].FilePath
	})
	for _, sec := range r.Secrets {
		sort.Slice(sec.Findings, func(i, j int) bool {
			if sec.Findings[i].RuleID != sec.Findings[j].RuleID {
				return sec.Findings[i].RuleID < sec.Findings[j].RuleID
			}
			return sec.Findings[i].StartLine < sec.Findings[j].StartLine
		})
	}

	// License files
	sort.Slice(r.Licenses, func(i, j int) bool {
		if r.Licenses[i].Type == r.Licenses[j].Type {
			if r.Licenses[i].FilePath == r.Licenses[j].FilePath {
				return r.Licenses[i].Layer.DiffID < r.Licenses[j].Layer.DiffID
			} else {
				return r.Licenses[i].FilePath < r.Licenses[j].FilePath
			}
		}

		return r.Licenses[i].Type < r.Licenses[j].Type
	})
}

func (r *AnalysisResult) Merge(new *AnalysisResult) {
	if new == nil || new.isEmpty() {
		return
	}

	// this struct is accessed by multiple goroutines
	r.m.Lock()
	defer r.m.Unlock()

	r.OS.Merge(new.OS)

	if new.Repository != nil {
		r.Repository = new.Repository
	}

	if len(new.PackageInfos) > 0 {
		r.PackageInfos = append(r.PackageInfos, new.PackageInfos...)
	}

	if len(new.Applications) > 0 {
		r.Applications = append(r.Applications, new.Applications...)
	}

	// Merge SHA-256 digests of unpackaged files
	if new.Digests != nil {
		r.Digests = lo.Assign(r.Digests, new.Digests)
	}

	for t, files := range new.Files {
		if v, ok := r.Files[t]; ok {
			r.Files[t] = append(v, files...)
		} else {
			r.Files[t] = files
		}
	}

	r.Secrets = append(r.Secrets, new.Secrets...)
	r.Licenses = append(r.Licenses, new.Licenses...)

	for packageRef, installedFiles := range new.SystemInstalledFiles {
		r.SystemInstalledFiles[packageRef] = append(r.SystemInstalledFiles[packageRef], installedFiles...)
	}

	if new.BuildInfo != nil {
		if r.BuildInfo == nil {
			r.BuildInfo = new.BuildInfo
		} else {
			// We don't need to merge build info here
			// because there is theoretically only one file about build info in each layer.
			if new.BuildInfo.Nvr != "" || new.BuildInfo.Arch != "" {
				r.BuildInfo.Nvr = new.BuildInfo.Nvr
				r.BuildInfo.Arch = new.BuildInfo.Arch
			}
			if len(new.BuildInfo.ContentSets) > 0 {
				r.BuildInfo.ContentSets = new.BuildInfo.ContentSets
			}
		}
	}

	r.CustomResources = append(r.CustomResources, new.CustomResources...)
}

func belongToGroup(groupName Group, analyzerType Type, disabledAnalyzers []Type, analyzer any) bool {
	if slices.Contains(disabledAnalyzers, analyzerType) {
		return false
	}

	analyzerGroupName := GroupBuiltin
	if cg, ok := analyzer.(CustomGroup); ok {
		analyzerGroupName = cg.Group()
	}
	if analyzerGroupName != groupName {
		return false
	}

	return true
}

const separator = ":"

func NewAnalyzerGroup(opt AnalyzerOptions) (AnalyzerGroup, error) {
	groupName := opt.Group
	if groupName == "" {
		groupName = GroupBuiltin
	}

	group := AnalyzerGroup{
		filePatterns: map[Type][]*regexp.Regexp{},
	}
	for _, p := range opt.FilePatterns {
		// e.g. "dockerfile:my_dockerfile_*"
		s := strings.SplitN(p, separator, 2)
		if len(s) != 2 {
			return group, xerrors.Errorf("invalid file pattern (%s)", p)
		}

		fileType, pattern := s[0], s[1]
		r, err := regexp.Compile(pattern)
		if err != nil {
			return group, xerrors.Errorf("invalid file regexp (%s): %w", p, err)
		}

		if _, ok := group.filePatterns[Type(fileType)]; !ok {
			group.filePatterns[Type(fileType)] = []*regexp.Regexp{}
		}

		group.filePatterns[Type(fileType)] = append(group.filePatterns[Type(fileType)], r)
	}

	for analyzerType, a := range analyzers {
		if !belongToGroup(groupName, analyzerType, opt.DisabledAnalyzers, a) {
			continue
		}
		// Initialize only scanners that have Init()
		if ini, ok := a.(Initializer); ok {
			if err := ini.Init(opt); err != nil {
				return AnalyzerGroup{}, xerrors.Errorf("analyzer initialization error: %w", err)
			}
		}
		group.analyzers = append(group.analyzers, a)
	}

	for analyzerType, a := range configAnalyzers {
		if slices.Contains(opt.DisabledAnalyzers, analyzerType) {
			continue
		}
		group.configAnalyzers = append(group.configAnalyzers, a)
	}

	return group, nil
}

// AnalyzerVersions returns analyzer version identifier used for cache keys.
func (ag AnalyzerGroup) AnalyzerVersions() map[string]int {
	versions := map[string]int{}
	for _, a := range ag.analyzers {
		versions[string(a.Type())] = a.Version()
	}
	return versions
}

// ImageConfigAnalyzerVersions returns analyzer version identifier used for cache keys.
func (ag AnalyzerGroup) ImageConfigAnalyzerVersions() map[string]int {
	versions := map[string]int{}
	for _, ca := range ag.configAnalyzers {
		versions[string(ca.Type())] = ca.Version()
	}
	return versions
}

func (ag AnalyzerGroup) AnalyzeFile(ctx context.Context, wg *sync.WaitGroup, limit *semaphore.Weighted, result *AnalysisResult,
	dir, filePath string, info os.FileInfo, opener Opener, disabled []Type, opts AnalysisOptions) error {
	if info.IsDir() {
		return nil
	}

	// filepath extracted from tar file doesn't have the prefix "/"
	cleanPath := strings.TrimLeft(filePath, "/")

	for _, a := range ag.analyzers {
		// Skip disabled analyzers
		if slices.Contains(disabled, a.Type()) {
			continue
		}

		if !ag.filePatternMatch(a.Type(), cleanPath) && !a.Required(cleanPath, info) {
			continue
		}
		rc, err := opener()
		if errors.Is(err, fs.ErrPermission) {
			log.Logger.Debugf("Permission error: %s", filePath)
			break
		} else if err != nil {
			return xerrors.Errorf("unable to open %s: %w", filePath, err)
		}

		if err = limit.Acquire(ctx, 1); err != nil {
			return xerrors.Errorf("semaphore acquire: %w", err)
		}
		wg.Add(1)

		go func(a analyzer, rc dio.ReadSeekCloserAt) {
			defer limit.Release(1)
			defer wg.Done()
			defer rc.Close()

			ret, err := a.Analyze(ctx, AnalysisInput{
				Dir:      dir,
				FilePath: filePath,
				Info:     info,
				Content:  rc,
				Options:  opts,
			})
			if err != nil && !xerrors.Is(err, aos.AnalyzeOSError) {
				log.Logger.Debugf("Analysis error: %s", err)
				return
			}
			if ret != nil {
				result.Merge(ret)
			}
		}(a, rc)
	}

	return nil
}

func (ag AnalyzerGroup) AnalyzeImageConfig(targetOS types.OS, config *v1.ConfigFile) *AnalysisResult {
	input := ConfigAnalysisInput{
		OS:     targetOS,
		Config: config,
	}
	result := NewAnalysisResult()
	for _, a := range ag.configAnalyzers {
		if !a.Required(targetOS) {
			continue
		}

		r, err := a.Analyze(input)
		if err != nil {
			log.Logger.Debugf("Image config analysis error: %s", err)
			continue
		}

		result.Merge(r)
	}
	return result
}

func (ag AnalyzerGroup) filePatternMatch(analyzerType Type, filePath string) bool {
	for _, pattern := range ag.filePatterns[analyzerType] {
		if pattern.MatchString(filePath) {
			return true
		}
	}
	return false
}
