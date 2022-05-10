package scanner

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	adapter "github.com/aquasecurity/defsec/adapters/cloudformation"

	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
)

type Scanner struct {
	includePassed     bool
	includeIgnored    bool
	excludedRuleIDs   []string
	ignoreCheckErrors bool
	paths             []string
	debugWriter       io.Writer
}

// New creates a new Scanner
func New(options ...Option) *Scanner {
	s := &Scanner{
		ignoreCheckErrors: true,
	}
	for _, option := range options {
		option(s)
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
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	if stat.IsDir() {
		s.debug("supplied path is a directory, searching for relevant files")
		if err := filepath.Walk(path, func(foundPath string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			if filepath.Ext(foundPath) == ".yaml" ||
				filepath.Ext(foundPath) == ".yml" ||
				filepath.Ext(foundPath) == ".json" {
				s.paths = append(s.paths, foundPath)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	s.paths = append(s.paths, path)
	return nil
}

func (s *Scanner) Scan() (results []rules.Result, err error) {

	cfParser := parser.New()
	contexts, err := cfParser.ParseFiles(s.paths...)
	if err != nil {
		return nil, err
	}

	for _, ctx := range contexts {
		if ctx == nil {
			continue
		}
		state := adapter.Adapt(*ctx)
		if state == nil {
			continue
		}
		for _, rule := range rules.GetRegistered() {
			s.debug("Executing rule: %s", rule.Rule().AVDID)
			evalResult := rule.Evaluate(state)
			if len(evalResult) > 0 {
				s.debug("Found %d results for %s", len(evalResult), rule.Rule().AVDID)
				for _, scanResult := range evalResult {
					if s.isExcluded(scanResult) {
						continue
					}

					ref := scanResult.Metadata().Reference()

					if ref == nil && scanResult.Metadata().Parent() != nil {
						ref = scanResult.Metadata().Parent().Reference()
					}

					reference := ref.(*parser.CFReference)

					if !isIgnored(scanResult) {
						description := getDescription(scanResult, reference)
						scanResult.OverrideDescription(description)
						if scanResult.Status() == rules.StatusPassed && !s.includePassed {
							continue
						}
						results = append(results, scanResult)
					}
				}
			}
		}
	}
	return results, nil
}

func (s *Scanner) isExcluded(result rules.Result) bool {
	for _, excluded := range s.excludedRuleIDs {
		if strings.EqualFold(excluded, result.Flatten().RuleID) {
			return true
		}
	}
	return false
}

func getDescription(scanResult rules.Result, location *parser.CFReference) string {
	if scanResult.Status() != rules.StatusPassed {
		return scanResult.Description()
	}
	return fmt.Sprintf("Resource '%s' passed check: %s", location.LogicalID(), scanResult.Rule().Summary)
}
