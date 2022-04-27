package scanner

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/tfsec/internal/pkg/custom"
	"github.com/aquasecurity/tfsec/version"
	semver "github.com/hashicorp/go-version"

	"github.com/aquasecurity/tfsec/internal/pkg/config"

	"github.com/aquasecurity/defsec/parsers/terraform/parser"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/pkg/executor"
)

type Scanner struct {
	parserOpt      []parser.Option
	executorOpt    []executor.Option
	dirs           map[string]struct{}
	forceAllDirs   bool
	customCheckDir string
	configFile     string
	debugWriter    io.Writer
}

type Metrics struct {
	Parser   parser.Metrics
	Executor executor.Metrics
	Timings  struct {
		Total time.Duration
	}
}

func New(options ...Option) *Scanner {
	s := &Scanner{
		dirs:        make(map[string]struct{}),
		debugWriter: ioutil.Discard,
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

func (s *Scanner) debug(format string, args ...interface{}) {
	if s.debugWriter == nil {
		return
	}
	prefix := "[debug:scan] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) AddPath(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		s.dirs[path] = struct{}{}
	} else {
		s.dirs[filepath.Dir(path)] = struct{}{}
	}
	return nil
}

func (s *Scanner) Scan() (rules.Results, Metrics, error) {

	var metrics Metrics
	if s.configFile != "" {
		conf, err := config.LoadConfig(s.configFile)
		if err == nil {
			s.executorOpt = append(s.executorOpt, executor.OptionWithConfig(*conf))
			s.debug("Loaded config file from %s.", s.configFile)
		} else {
			s.debug("Failed to load config file from %s: %s", s.configFile, err)
		}
		if !s.minVersionSatisfied(conf) {
			return nil, metrics, fmt.Errorf("minimum tfsec version requirement not satisfied")
		}
		if conf.MinimumSeverity != "" {
			OptionWithMinimumSeverity(severity.StringToSeverity(conf.MinimumSeverity))(s)
		}
	}
	if s.customCheckDir != "" {
		if err := custom.Load(s.customCheckDir); err != nil {
			s.debug("Failed to load custom checks from %s: %s", s.customCheckDir, err)
			return nil, metrics, err
		}
	}

	// don't scan child directories that have parent directories containing tf files!
	var dirs []string
	for dir := range s.dirs {
		dirs = append(dirs, dir)
	}
	simplifiedDirs := s.removeNestedDirs(dirs)

	// find directories which directly contain tf files (and have no parent containing tf files)
	rootDirs := s.findRootModules(simplifiedDirs)
	sort.Strings(rootDirs)

	var allResults rules.Results

	// parse all root module directories
	for _, dir := range rootDirs {

		p := parser.New(s.parserOpt...)
		e := executor.New(s.executorOpt...)

		if err := p.ParseDirectory(dir); err != nil {
			return nil, metrics, err
		}

		modules, _, err := p.EvaluateAll()
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

		metrics.Executor.Counts.Passed += execMetrics.Counts.Passed
		metrics.Executor.Counts.Failed += execMetrics.Counts.Failed
		metrics.Executor.Counts.Ignored += execMetrics.Counts.Ignored
		metrics.Executor.Counts.Excluded += execMetrics.Counts.Excluded
		metrics.Executor.Counts.Critical += execMetrics.Counts.Critical
		metrics.Executor.Counts.High += execMetrics.Counts.High
		metrics.Executor.Counts.Medium += execMetrics.Counts.Medium
		metrics.Executor.Counts.Low += execMetrics.Counts.Low
		metrics.Executor.Timings.Adaptation += execMetrics.Timings.Adaptation
		metrics.Executor.Timings.RunningChecks += execMetrics.Timings.RunningChecks

		allResults = append(allResults, results...)
	}

	metrics.Timings.Total += metrics.Parser.Timings.DiskIODuration
	metrics.Timings.Total += metrics.Parser.Timings.ParseDuration
	metrics.Timings.Total += metrics.Executor.Timings.Adaptation
	metrics.Timings.Total += metrics.Executor.Timings.RunningChecks

	return allResults, metrics, nil
}

func (s *Scanner) minVersionSatisfied(conf *config.Config) bool {

	s.debug("Checking if min tfsec version configured")
	if conf.MinimumRequiredVersion == "" {
		s.debug("No minimum tfsec version specified in the config")
		return true
	}
	s.debug("Comparing required version [%s] against current version [%s]", conf.MinimumRequiredVersion, version.Version)

	v1, err := semver.NewVersion(conf.MinimumRequiredVersion)
	if err != nil {
		s.debug("There was an error parsing the config min required version: %w", err)
		return true
	}
	v2, err := semver.NewVersion(version.Version)
	if err != nil {
		s.debug("There was an error parsing the current version: %w", err)
		return true
	}
	return v2.GreaterThanOrEqual(v1)
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

func (s *Scanner) findRootModules(dirs []string) []string {

	var roots []string
	var others []string

	for _, dir := range dirs {
		if isRootModule(dir) {
			roots = append(roots, dir)
			if !s.forceAllDirs {
				continue
			}
		}

		// if this isn't a root module, look at directories inside it
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, file := range files {
			file := resolveSymlink(dir, file)
			if file.IsDir() {
				others = append(others, filepath.Join(dir, file.Name()))
			}
		}
	}

	if (len(roots) == 0 || s.forceAllDirs) && len(others) > 0 {
		roots = append(roots, s.findRootModules(others)...)
	}

	return s.removeNestedDirs(roots)
}

func resolveSymlink(dir string, file os.FileInfo) os.FileInfo {

	if resolvedLink, err := os.Readlink(filepath.Join(dir, file.Name())); err == nil {
		resolvedPath := filepath.Clean(filepath.Join(dir, resolvedLink))
		if info, err := os.Lstat(resolvedPath); err == nil {
			return info
		}
	}
	return file
}

func isRootModule(dir string) bool {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".tf") || strings.HasSuffix(file.Name(), ".tf.json") {
			return true
		}
	}
	return false
}
