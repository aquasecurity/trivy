package terraform

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/executor"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)
var _ options.RawConfigScanner = (*Scanner)(nil)
var _ ConfigurableTerraformScanner = (*Scanner)(nil)

type Scanner struct {
	*rego.RegoScannerProvider
	logger       *log.Logger
	options      []options.ScannerOption
	parserOpt    []parser.Option
	executorOpt  []executor.Option
	dirs         set.Set[string]
	forceAllDirs bool
	execLock     sync.RWMutex
}

func (s *Scanner) Name() string {
	return "Terraform"
}

func (s *Scanner) SetForceAllDirs(b bool) {
	s.forceAllDirs = b
}

func (s *Scanner) SetScanRawConfig(b bool) {
	s.AddExecutorOptions(executor.OptionWithScanRawConfig(b))
}

func (s *Scanner) AddParserOptions(opts ...parser.Option) {
	s.parserOpt = append(s.parserOpt, opts...)
}

func (s *Scanner) AddExecutorOptions(opts ...executor.Option) {
	s.executorOpt = append(s.executorOpt, opts...)
}

func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		RegoScannerProvider: rego.NewRegoScannerProvider(opts...),
		dirs:                set.New[string](),
		options:             opts,
		logger:              log.WithPrefix("terraform scanner"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// terraformRootModule represents the module to be used as the root module for Terraform deployment.
type terraformRootModule struct {
	rootPath string
	childs   terraform.Modules
	fsMap    map[string]fs.FS
}

func (s *Scanner) ScanFS(ctx context.Context, target fs.FS, dir string) (scan.Results, error) {

	s.logger.Debug("Scanning directory", log.FilePath(dir))

	// find directories which directly contain tf files
	modulePaths := s.findModules(target, dir, dir)
	sort.Strings(modulePaths)

	if len(modulePaths) == 0 {
		s.logger.Info("No modules found, skipping directory", log.FilePath(dir))
		return nil, nil
	}

	rs, err := s.InitRegoScanner(target, s.options)
	if err != nil {
		return nil, fmt.Errorf("init rego scanner: %w", err)
	}

	s.execLock.Lock()
	s.executorOpt = append(s.executorOpt, executor.OptionWithRegoScanner(rs))
	s.execLock.Unlock()

	var allResults scan.Results

	p := parser.New(target, "", s.parserOpt...)
	rootDirs, err := p.FindRootModules(ctx, modulePaths)
	if err != nil {
		return nil, fmt.Errorf("failed to find root modules: %w", err)
	}

	rootModules := make([]terraformRootModule, 0, len(rootDirs))

	// parse all root module directories
	for _, dir := range rootDirs {

		s.logger.Info("Scanning root module", log.FilePath(dir))

		p := parser.New(target, "", s.parserOpt...)

		if err := p.ParseFS(ctx, dir); err != nil {
			return nil, err
		}

		modules, err := p.EvaluateAll(ctx)
		if err != nil {
			return nil, err
		}

		rootModules = append(rootModules, terraformRootModule{
			rootPath: dir,
			childs:   modules,
			fsMap:    p.GetFilesystemMap(),
		})
	}

	for _, module := range rootModules {
		s.execLock.RLock()
		e := executor.New(s.executorOpt...)
		s.execLock.RUnlock()
		results, err := e.Execute(ctx, module.childs, module.rootPath)
		if err != nil {
			return nil, err
		}

		for i, result := range results {
			if result.Metadata().Range().GetFS() != nil {
				continue
			}
			key := result.Metadata().Range().GetFSKey()
			if key == "" {
				continue
			}
			if filesystem, ok := module.fsMap[key]; ok {
				override := scan.Results{
					result,
				}
				override.SetSourceAndFilesystem(result.Range().GetSourcePrefix(), filesystem, false)
				results[i] = override[0]
			}
		}

		allResults = append(allResults, results...)
	}

	return allResults, nil
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

func (s *Scanner) findModules(target fs.FS, scanDir string, dirs ...string) []string {

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
			if file.IsDir() {
				others = append(others, path.Join(dir, file.Name()))
			}
		}
	}

	if (len(roots) == 0 || s.forceAllDirs) && len(others) > 0 {
		roots = append(roots, s.findModules(target, scanDir, others...)...)
	}

	return s.removeNestedDirs(roots)
}

func (s *Scanner) isRootModule(target fs.FS, dir string) bool {
	files, err := fs.ReadDir(target, filepath.ToSlash(dir))
	if err != nil {
		s.logger.Error("Failed to read dir", log.FilePath(dir), log.Err(err))
		return false
	}
	suffixes := []string{".tf", ".tf.json", ".tofu", ".tofu.json"}

	for _, file := range files {
		for _, suf := range suffixes {
			if strings.HasSuffix(file.Name(), suf) {
				return true
			}
		}
	}
	return false
}
