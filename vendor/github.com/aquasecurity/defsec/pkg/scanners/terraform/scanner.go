package terraform

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/defsec/internal/debug"
	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/scanners"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/executor"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser/resolvers"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/extrafs"
)

var _ scanners.Scanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)
var _ ConfigurableTerraformScanner = (*Scanner)(nil)

type Scanner struct {
	options                 []options.ScannerOption
	parserOpt               []options.ParserOption
	executorOpt             []executor.Option
	dirs                    map[string]struct{}
	forceAllDirs            bool
	policyDirs              []string
	policyReaders           []io.Reader
	regoScanner             *rego.Scanner
	execLock                sync.RWMutex
	debug                   debug.Logger
	enableEmbeddedLibraries bool
	sync.Mutex
	loadEmbedded bool
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	s.loadEmbedded = b
}

func (s *Scanner) SetEmbeddedLibrariesEnabled(enabled bool) {
	s.enableEmbeddedLibraries = enabled
}

func (s *Scanner) Name() string {
	return "Terraform"
}

func (s *Scanner) SetForceAllDirs(b bool) {
	s.forceAllDirs = b
}

func (s *Scanner) AddParserOptions(options ...options.ParserOption) {
	s.parserOpt = append(s.parserOpt, options...)
}

func (s *Scanner) AddExecutorOptions(options ...executor.Option) {
	s.executorOpt = append(s.executorOpt, options...)
}

func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	s.policyReaders = readers
}

func (s *Scanner) SetSkipRequiredCheck(skip bool) {
	s.parserOpt = append(s.parserOpt, options.ParserWithSkipRequiredCheck(skip))
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.parserOpt = append(s.parserOpt, options.ParserWithDebug(writer))
	s.debug = debug.New(writer, "scan:terraform")
}

func (s *Scanner) SetTraceWriter(_ io.Writer) {
}

func (s *Scanner) SetPerResultTracingEnabled(_ bool) {
}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetDataDirs(_ ...string) {
}

func (s *Scanner) SetPolicyNamespaces(_ ...string) {
}

func (s *Scanner) SetPolicyFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}

type Metrics struct {
	Parser   parser.Metrics
	Executor executor.Metrics
	Timings  struct {
		Total time.Duration
	}
}

func New(options ...options.ScannerOption) *Scanner {
	s := &Scanner{
		dirs:    make(map[string]struct{}),
		options: options,
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

func (s *Scanner) ScanFS(ctx context.Context, target fs.FS, dir string) (scan.Results, error) {
	results, _, err := s.ScanFSWithMetrics(ctx, target, dir)
	return results, err
}

func (s *Scanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.Lock()
	defer s.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoScanner := rego.NewScanner(s.options...)
	if s.enableEmbeddedLibraries {
		if err := regoScanner.LoadEmbeddedLibraries(); err != nil {
			return nil, fmt.Errorf("failed to load embedded libraries: %w", err)
		}
	}
	if err := regoScanner.LoadPolicies(s.loadEmbedded, srcFS, s.policyDirs, s.policyReaders); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func (s *Scanner) ScanFSWithMetrics(ctx context.Context, target fs.FS, dir string) (scan.Results, Metrics, error) {

	var metrics Metrics

	s.debug.Log("scanning [%s] at %s", target, dir)

	// find directories which directly contain tf files (and have no parent containing tf files)
	rootDirs := s.findRootModules(target, dir, dir)
	sort.Strings(rootDirs)

	if len(rootDirs) == 0 {
		s.debug.Log("no root modules found")
		return nil, metrics, nil
	}

	regoScanner, err := s.initRegoScanner(target)
	if err != nil {
		return nil, metrics, err
	}

	s.execLock.Lock()
	s.executorOpt = append(s.executorOpt, executor.OptionWithRegoScanner(regoScanner))
	s.execLock.Unlock()

	var allResults scan.Results

	// parse all root module directories
	for _, dir := range rootDirs {

		s.debug.Log("Scanning root module '%s'...", dir)

		p := parser.New(target, "", s.parserOpt...)
		s.execLock.RLock()
		e := executor.New(s.executorOpt...)
		s.execLock.RUnlock()

		if err := p.ParseFS(ctx, dir); err != nil {
			return nil, metrics, err
		}

		modules, _, err := p.EvaluateAll(ctx)
		if err != nil {
			return nil, metrics, err
		}

		parserMetrics := p.Metrics()
		metrics.Parser.Counts.Blocks += parserMetrics.Counts.Blocks
		metrics.Parser.Counts.Modules += parserMetrics.Counts.Modules
		metrics.Parser.Counts.Files += parserMetrics.Counts.Files
		metrics.Parser.Timings.DiskIODuration += parserMetrics.Timings.DiskIODuration
		metrics.Parser.Timings.ParseDuration += parserMetrics.Timings.ParseDuration

		results, execMetrics, err := e.Execute(modules)
		if err != nil {
			return nil, metrics, err
		}

		fsMap := p.GetFilesystemMap()
		for i, result := range results {
			if result.Metadata().Range().GetFS() != nil {
				continue
			}
			key := result.Metadata().Range().GetFSKey()
			if key == "" {
				continue
			}
			if filesystem, ok := fsMap[key]; ok {
				override := scan.Results{
					result,
				}
				override.SetSourceAndFilesystem(result.Range().GetSourcePrefix(), filesystem)
				results[i] = override[0]
			}
		}

		metrics.Executor.Counts.Passed += execMetrics.Counts.Passed
		metrics.Executor.Counts.Failed += execMetrics.Counts.Failed
		metrics.Executor.Counts.Ignored += execMetrics.Counts.Ignored
		metrics.Executor.Counts.Critical += execMetrics.Counts.Critical
		metrics.Executor.Counts.High += execMetrics.Counts.High
		metrics.Executor.Counts.Medium += execMetrics.Counts.Medium
		metrics.Executor.Counts.Low += execMetrics.Counts.Low
		metrics.Executor.Timings.Adaptation += execMetrics.Timings.Adaptation
		metrics.Executor.Timings.RunningChecks += execMetrics.Timings.RunningChecks

		allResults = append(allResults, results...)
	}

	metrics.Parser.Counts.ModuleDownloads = resolvers.Remote.GetDownloadCount()

	metrics.Timings.Total += metrics.Parser.Timings.DiskIODuration
	metrics.Timings.Total += metrics.Parser.Timings.ParseDuration
	metrics.Timings.Total += metrics.Executor.Timings.Adaptation
	metrics.Timings.Total += metrics.Executor.Timings.RunningChecks

	return allResults, metrics, nil
}

func (s *Scanner) removeNestedDirs(dirs []string) []string {
	if s.forceAllDirs {
		return dirs
	}
	var clean []string
	for _, dirA := range dirs {
		dirOK := true
		for _, dirB := range dirs {
			if dirA == dirB {
				continue
			}
			if str, err := filepath.Rel(dirB, dirA); err == nil && !strings.HasPrefix(str, "..") {
				dirOK = false
				break
			}
		}
		if dirOK {
			clean = append(clean, dirA)
		}
	}
	return clean
}

func (s *Scanner) findRootModules(target fs.FS, scanDir string, dirs ...string) []string {

	var roots []string
	var others []string

	for _, dir := range dirs {
		if s.isRootModule(target, dir) {
			roots = append(roots, dir)
			if !s.forceAllDirs {
				continue
			}
		}

		// if this isn't a root module, look at directories inside it
		files, err := fs.ReadDir(target, filepath.ToSlash(dir))
		if err != nil {
			continue
		}
		for _, file := range files {
			realPath := filepath.Join(dir, file.Name())
			if symFS, ok := target.(extrafs.ReadLinkFS); ok {
				realPath, err = symFS.ResolveSymlink(realPath, scanDir)
				if err != nil {
					s.debug.Log("failed to resolve symlink '%s': %s", file.Name(), err)
					continue
				}
			}
			if file.IsDir() {
				others = append(others, realPath)
			} else if statFS, ok := target.(fs.StatFS); ok {
				info, err := statFS.Stat(filepath.ToSlash(realPath))
				if err != nil {
					continue
				}
				if info.IsDir() {
					others = append(others, realPath)
				}
			}
		}
	}

	if (len(roots) == 0 || s.forceAllDirs) && len(others) > 0 {
		roots = append(roots, s.findRootModules(target, scanDir, others...)...)
	}

	return s.removeNestedDirs(roots)
}

func (s *Scanner) isRootModule(target fs.FS, dir string) bool {
	files, err := fs.ReadDir(target, filepath.ToSlash(dir))
	if err != nil {
		s.debug.Log("failed to read dir '%s' from filesystem [%s]: %s", dir, target, err)
		return false
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".tf") || strings.HasSuffix(file.Name(), ".tf.json") {
			return true
		}
	}
	return false
}
