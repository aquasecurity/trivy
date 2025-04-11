package analyzer

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/samber/lo"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/misconf"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	analyzers     = make(map[Type]analyzer)
	postAnalyzers = make(map[Type]postAnalyzerInitialize)

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
	Parallel             int
	FilePatterns         []string
	DisabledAnalyzers    []Type
	DetectionPriority    types.DetectionPriority
	MisconfScannerOption misconf.ScannerOption
	SecretScannerOption  SecretScannerOption
	LicenseScannerOption LicenseScannerOption
}

type SecretScannerOption struct {
	ConfigPath string
}

type LicenseScannerOption struct {
	// Use license classifier to get better results though the classification is expensive.
	Full                      bool
	ClassifierConfidenceLevel float64
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

type PostAnalyzer interface {
	Type() Type
	Version() int
	PostAnalyze(ctx context.Context, input PostAnalysisInput) (*AnalysisResult, error)
	Required(filePath string, info os.FileInfo) bool
}

////////////////////
// Analyzer group //
////////////////////

type Group string

const GroupBuiltin Group = "builtin"

func RegisterAnalyzer(analyzer analyzer) {
	if _, ok := analyzers[analyzer.Type()]; ok {
		log.Fatal("Analyzer is registered twice", log.String("type", string(analyzer.Type())))
	}
	analyzers[analyzer.Type()] = analyzer
}

type postAnalyzerInitialize func(options AnalyzerOptions) (PostAnalyzer, error)

func RegisterPostAnalyzer(t Type, initializer postAnalyzerInitialize) {
	if _, ok := postAnalyzers[t]; ok {
		log.Fatal("Analyzer is registered twice", log.String("type", string(t)))
	}
	postAnalyzers[t] = initializer
}

// DeregisterAnalyzer is mainly for testing
func DeregisterAnalyzer(t Type) {
	delete(analyzers, t)
}

// CustomGroup returns a group name for custom analyzers
// This is mainly intended to be used in Aqua products.
type CustomGroup interface {
	Group() Group
}

// StaticPathAnalyzer is an interface for analyzers that can specify static file paths
// instead of traversing the entire filesystem.
type StaticPathAnalyzer interface {
	// StaticPaths returns a list of static file paths to analyze
	StaticPaths() []string
}

type Opener func() (xio.ReadSeekCloserAt, error)

type AnalyzerGroup struct {
	logger            *log.Logger
	analyzers         []analyzer
	postAnalyzers     []PostAnalyzer
	filePatterns      map[Type]FilePatterns
	detectionPriority types.DetectionPriority
}

///////////////////////////
// Analyzer input/output //
///////////////////////////

type AnalysisInput struct {
	Dir      string
	FilePath string
	Info     os.FileInfo
	Content  xio.ReadSeekerAt

	Options AnalysisOptions
}

type PostAnalysisInput struct {
	FS           fs.FS
	FilePatterns FilePatterns
	Options      AnalysisOptions
}

type FilePatterns []*regexp.Regexp

func (f FilePatterns) Match(filePath string) bool {
	for _, pattern := range f {
		if pattern.MatchString(filePath) {
			return true
		}
	}
	return false
}

type AnalysisOptions struct {
	Offline      bool
	FileChecksum bool
}

type AnalysisResult struct {
	m                    sync.Mutex
	OS                   types.OS
	Repository           *types.Repository
	PackageInfos         []types.PackageInfo
	Applications         []types.Application
	Misconfigurations    []types.Misconfiguration
	Secrets              []types.Secret
	Licenses             []types.LicenseFile
	SystemInstalledFiles []string // A list of files installed by OS package manager

	// Digests contains SHA-256 digests of unpackaged files
	// used to search for SBOM attestation.
	Digests map[string]string

	// For Red Hat
	BuildInfo *types.BuildInfo

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []types.CustomResource
}

func NewAnalysisResult() *AnalysisResult {
	result := new(AnalysisResult)
	return result
}

func (r *AnalysisResult) isEmpty() bool {
	return lo.IsEmpty(r.OS) && r.Repository == nil && len(r.PackageInfos) == 0 && len(r.Applications) == 0 &&
		len(r.Misconfigurations) == 0 && len(r.Secrets) == 0 && len(r.Licenses) == 0 && len(r.SystemInstalledFiles) == 0 &&
		r.BuildInfo == nil && len(r.Digests) == 0 && len(r.CustomResources) == 0
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
		if r.Applications[i].FilePath != r.Applications[j].FilePath {
			return r.Applications[i].FilePath < r.Applications[j].FilePath
		}
		return r.Applications[i].Type < r.Applications[j].Type
	})

	for _, app := range r.Applications {
		sort.Sort(app.Packages)
	}

	// Custom resources
	sort.Slice(r.CustomResources, func(i, j int) bool {
		return r.CustomResources[i].FilePath < r.CustomResources[j].FilePath
	})

	// Misconfigurations
	sort.Slice(r.Misconfigurations, func(i, j int) bool {
		if r.Misconfigurations[i].FileType != r.Misconfigurations[j].FileType {
			return r.Misconfigurations[i].FileType < r.Misconfigurations[j].FileType
		} else {
			return r.Misconfigurations[i].FilePath < r.Misconfigurations[j].FilePath
		}
	})

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

func (r *AnalysisResult) Merge(newResult *AnalysisResult) {
	if newResult == nil || newResult.isEmpty() {
		return
	}

	// this struct is accessed by multiple goroutines
	r.m.Lock()
	defer r.m.Unlock()

	r.OS.Merge(newResult.OS)

	if newResult.Repository != nil {
		r.Repository = newResult.Repository
	}

	if len(newResult.PackageInfos) > 0 {
		r.PackageInfos = append(r.PackageInfos, newResult.PackageInfos...)
	}

	if len(newResult.Applications) > 0 {
		r.Applications = append(r.Applications, newResult.Applications...)
	}

	// Merge SHA-256 digests of unpackaged files
	if newResult.Digests != nil {
		r.Digests = lo.Assign(r.Digests, newResult.Digests)
	}

	r.Misconfigurations = append(r.Misconfigurations, newResult.Misconfigurations...)
	r.Secrets = append(r.Secrets, newResult.Secrets...)
	r.Licenses = append(r.Licenses, newResult.Licenses...)
	r.SystemInstalledFiles = append(r.SystemInstalledFiles, newResult.SystemInstalledFiles...)

	if newResult.BuildInfo != nil {
		if r.BuildInfo == nil {
			r.BuildInfo = newResult.BuildInfo
		} else {
			// We don't need to merge build info here
			// because there is theoretically only one file about build info in each layer.
			if newResult.BuildInfo.Nvr != "" || newResult.BuildInfo.Arch != "" {
				r.BuildInfo.Nvr = newResult.BuildInfo.Nvr
				r.BuildInfo.Arch = newResult.BuildInfo.Arch
			}
			if len(newResult.BuildInfo.ContentSets) > 0 {
				r.BuildInfo.ContentSets = newResult.BuildInfo.ContentSets
			}
		}
	}

	r.CustomResources = append(r.CustomResources, newResult.CustomResources...)
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

func NewAnalyzerGroup(opts AnalyzerOptions) (AnalyzerGroup, error) {
	groupName := opts.Group
	if groupName == "" {
		groupName = GroupBuiltin
	}

	group := AnalyzerGroup{
		logger:            log.WithPrefix("analyzer"),
		filePatterns:      make(map[Type]FilePatterns),
		detectionPriority: opts.DetectionPriority,
	}
	for _, p := range opts.FilePatterns {
		// e.g. "dockerfile:my_dockerfile_*"
		s := strings.SplitN(p, separator, 2)
		if len(s) != 2 {
			return group, xerrors.Errorf("invalid file pattern (%s) expected format: \"fileType:regexPattern\" e.g. \"dockerfile:my_dockerfile_*\"", p)
		}

		fileType, pattern := s[0], s[1]
		r, err := regexp.Compile(pattern)
		if err != nil {
			return group, xerrors.Errorf("invalid file regexp (%s): %w", p, err)
		}

		group.filePatterns[Type(fileType)] = append(group.filePatterns[Type(fileType)], r)
	}

	for analyzerType, a := range analyzers {
		if !belongToGroup(groupName, analyzerType, opts.DisabledAnalyzers, a) {
			continue
		}
		// Initialize only scanners that have Init()
		if ini, ok := a.(Initializer); ok {
			if err := ini.Init(opts); err != nil {
				return AnalyzerGroup{}, xerrors.Errorf("analyzer initialization error: %w", err)
			}
		}
		group.analyzers = append(group.analyzers, a)
	}

	for analyzerType, init := range postAnalyzers {
		a, err := init(opts)
		if err != nil {
			return AnalyzerGroup{}, xerrors.Errorf("post-analyzer init error: %w", err)
		}
		if !belongToGroup(groupName, analyzerType, opts.DisabledAnalyzers, a) {
			continue
		}
		group.postAnalyzers = append(group.postAnalyzers, a)
	}

	return group, nil
}

type Versions struct {
	Analyzers     map[string]int
	PostAnalyzers map[string]int
}

// AnalyzerVersions returns analyzer version identifier used for cache keys.
func (ag AnalyzerGroup) AnalyzerVersions() Versions {
	analyzerVersions := make(map[string]int)
	for _, a := range ag.analyzers {
		analyzerVersions[string(a.Type())] = a.Version()
	}
	postAnalyzerVersions := make(map[string]int)
	for _, a := range ag.postAnalyzers {
		postAnalyzerVersions[string(a.Type())] = a.Version()
	}
	return Versions{
		Analyzers:     analyzerVersions,
		PostAnalyzers: postAnalyzerVersions,
	}
}

// AnalyzeFile determines which files are required by the analyzers based on the file name and attributes,
// and passes only those files to the analyzer for analysis.
// This function may be called concurrently and must be thread-safe.
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

		if !ag.filePatterns[a.Type()].Match(cleanPath) && !a.Required(cleanPath, info) {
			continue
		}
		rc, err := opener()
		if errors.Is(err, fs.ErrPermission) {
			ag.logger.Debug("Permission error", log.FilePath(filePath))
			break
		} else if err != nil {
			return xerrors.Errorf("unable to open %s: %w", filePath, err)
		}

		if err = limit.Acquire(ctx, 1); err != nil {
			return xerrors.Errorf("semaphore acquire: %w", err)
		}
		wg.Add(1)

		go func(a analyzer, rc xio.ReadSeekCloserAt) {
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
			if err != nil && !errors.Is(err, fos.AnalyzeOSError) {
				ag.logger.Debug("Analysis error", log.Err(err))
				return
			}
			result.Merge(ret)
		}(a, rc)
	}

	return nil
}

// RequiredPostAnalyzers returns a list of analyzer types that require the given file.
func (ag AnalyzerGroup) RequiredPostAnalyzers(filePath string, info os.FileInfo) []Type {
	if info.IsDir() {
		return nil
	}
	var postAnalyzerTypes []Type
	for _, a := range ag.postAnalyzers {
		if ag.filePatterns[a.Type()].Match(filePath) || a.Required(filePath, info) {
			postAnalyzerTypes = append(postAnalyzerTypes, a.Type())
		}
	}
	return postAnalyzerTypes
}

// PostAnalyze passes a virtual filesystem containing only required files
// and passes it to the respective post-analyzer.
// The obtained results are merged into the "result".
// This function may be called concurrently and must be thread-safe.
func (ag AnalyzerGroup) PostAnalyze(ctx context.Context, compositeFS *CompositeFS, result *AnalysisResult,
	opts AnalysisOptions) error {
	for _, a := range ag.postAnalyzers {
		fsys, ok := compositeFS.Get(a.Type())
		if !ok {
			continue
		}

		skippedFiles := result.SystemInstalledFiles
		if ag.detectionPriority == types.PriorityComprehensive {
			// If the detection priority is comprehensive, system files installed by the OS package manager will not be skipped.
			// It can lead to false positives and duplicates, but it may be necessary to detect all possible vulnerabilities.
			skippedFiles = nil
		}
		for _, app := range result.Applications {
			skippedFiles = append(skippedFiles, app.FilePath)
			for _, pkg := range app.Packages {
				// The analysis result could contain packages listed in SBOM.
				// The files of those packages don't have to be analyzed.
				// This is especially helpful for expensive post-analyzers such as the JAR analyzer.
				if pkg.FilePath != "" {
					skippedFiles = append(skippedFiles, pkg.FilePath)
				}
			}
		}

		filteredFS, err := fsys.Filter(skippedFiles)
		if err != nil {
			return xerrors.Errorf("unable to filter filesystem: %w", err)
		}

		res, err := a.PostAnalyze(ctx, PostAnalysisInput{
			FS:           filteredFS,
			FilePatterns: ag.filePatterns[a.Type()],
			Options:      opts,
		})
		if err != nil {
			return xerrors.Errorf("post analysis error: %w", err)
		}
		result.Merge(res)
	}
	return nil
}

// PostAnalyzerFS returns a composite filesystem that contains multiple filesystems for each post-analyzer
func (ag AnalyzerGroup) PostAnalyzerFS() (*CompositeFS, error) {
	return NewCompositeFS()
}

// StaticPaths collects static paths from all enabled analyzers
// It returns the collected paths and a boolean indicating if all enabled analyzers implement StaticPathAnalyzer
func (ag AnalyzerGroup) StaticPaths(disabled []Type) ([]string, bool) {
	var paths []string

	for _, a := range ag.analyzers {
		// Skip disabled analyzers
		if slices.Contains(disabled, a.Type()) {
			continue
		}

		// We can't be sure that the file pattern uses a static path.
		// So we don't need to use `StaticPath` logic if any enabled analyzer has a file pattern.
		if _, ok := ag.filePatterns[a.Type()]; ok {
			return nil, false
		}

		// If any analyzer doesn't implement StaticPathAnalyzer, return false
		staticPathAnalyzer, ok := a.(StaticPathAnalyzer)
		if !ok {
			return nil, false
		}

		// Collect paths from StaticPathAnalyzer
		paths = append(paths, staticPathAnalyzer.StaticPaths()...)
	}

	// PostAnalyzers don't implement StaticPathAnalyzer.
	// So if at least one postAnalyzer is enabled - we should not use StaticPath.
	if allPostAnalyzersDisabled := lo.EveryBy(ag.postAnalyzers, func(a PostAnalyzer) bool {
		return slices.Contains(disabled, a.Type())
	}); !allPostAnalyzersDisabled {
		return nil, false
	}

	// Remove duplicates
	return lo.Uniq(paths), true
}
