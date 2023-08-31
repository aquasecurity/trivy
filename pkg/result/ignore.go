package result

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/log"
)

// IgnoreFinding represents an item to be ignored.
type IgnoreFinding struct {
	// ID is the identifier of the vulnerability, misconfiguration, secret, or license.
	// e.g. CVE-2019-8331, AVD-AWS-0175, etc.
	// required: true
	ID string `yaml:"id"`

	// Paths is the list of file paths to be ignored.
	// If Paths is not set, the ignore finding is applied to all files.
	// required: false
	Paths []string `yaml:"paths"`

	// ExpiredAt is the expiration date of the ignore finding.
	// If ExpiredAt is not set, the ignore finding is always valid.
	// required: false
	ExpiredAt time.Time `yaml:"expired_at"`

	// Statement describes the reason for ignoring the finding.
	// required: false
	Statement string `yaml:"statement"`
}

type IgnoreFindings []IgnoreFinding

func (f *IgnoreFindings) Match(path, id string) bool {
	for _, finding := range *f {
		if id != finding.ID {
			continue
		}

		if !pathMatch(path, finding.Paths) {
			continue
		}
		log.Logger.Debugw("Ignored", log.String("id", id), log.String("path", path))
		return true

	}
	return false
}

func pathMatch(path string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}

	for _, pattern := range patterns {
		// Patterns are already validated, so we ignore errors here
		if matched, _ := doublestar.Match(pattern, path); matched {
			return true
		}
	}
	return false
}

func (f *IgnoreFindings) Filter() {
	var findings IgnoreFindings
	for _, finding := range *f {
		// Filter out expired ignore findings
		if !finding.ExpiredAt.IsZero() && finding.ExpiredAt.Before(clock.Now()) {
			continue
		}

		// Filter out invalid path patterns
		finding.Paths = lo.Filter(finding.Paths, func(pattern string, _ int) bool {
			if !doublestar.ValidatePattern(pattern) {
				log.Logger.Errorf("Invalid path pattern in the ignore file: %q", pattern)
				return false
			}
			return true
		})
		findings = append(findings, finding)
	}
	*f = findings
}

// IgnoreConfig represents the structure of .trivyignore.yaml.
type IgnoreConfig struct {
	Vulnerabilities   IgnoreFindings `yaml:"vulnerabilities"`
	Misconfigurations IgnoreFindings `yaml:"misconfigurations"`
	Secrets           IgnoreFindings `yaml:"secrets"`
	Licenses          IgnoreFindings `yaml:"licenses"`
}

func getIgnoredFindings(ignoreFile string) (IgnoreConfig, error) {
	var conf IgnoreConfig
	if _, err := os.Stat(ignoreFile); errors.Is(err, fs.ErrNotExist) {
		// .trivyignore doesn't necessarily exist
		return IgnoreConfig{}, nil
	} else if filepath.Ext(ignoreFile) == ".yml" || filepath.Ext(ignoreFile) == ".yaml" {
		conf, err = parseIgnoreYAML(ignoreFile)
		if err != nil {
			return IgnoreConfig{}, xerrors.Errorf("%s parse error: %w", ignoreFile, err)
		}
	} else {
		ignoredFindings, err := parseIgnore(ignoreFile)
		if err != nil {
			return IgnoreConfig{}, xerrors.Errorf("%s parse error: %w", ignoreFile, err)
		}

		// IDs in .trivyignore are treated as IDs for all scanners
		// as it is unclear which type of security issue they are
		conf = IgnoreConfig{
			Vulnerabilities:   ignoredFindings,
			Misconfigurations: ignoredFindings,
			Secrets:           ignoredFindings,
			Licenses:          ignoredFindings,
		}
	}

	conf.Vulnerabilities.Filter()
	conf.Misconfigurations.Filter()
	conf.Secrets.Filter()
	conf.Licenses.Filter()

	return conf, nil
}

func parseIgnoreYAML(ignoreFile string) (IgnoreConfig, error) {
	// Read .trivyignore.yaml
	f, err := os.Open(ignoreFile)
	if err != nil {
		return IgnoreConfig{}, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()
	log.Logger.Debugf("Found an ignore yaml: %s", ignoreFile)

	// Parse the YAML content
	var ignoreConfig IgnoreConfig
	if err = yaml.NewDecoder(f).Decode(&ignoreConfig); err != nil {
		return IgnoreConfig{}, xerrors.Errorf("yaml decode error: %w", err)
	}
	return ignoreConfig, nil
}

func parseIgnore(ignoreFile string) (IgnoreFindings, error) {
	f, err := os.Open(ignoreFile)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()
	log.Logger.Debugf("Found an ignore file: %s", ignoreFile)

	var ignoredFindings IgnoreFindings
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// Process all fields
		var exp time.Time
		fields := strings.Fields(line)
		if len(fields) > 1 {
			exp, err = getExpirationDate(fields)
			if err != nil {
				log.Logger.Warnf("Error while parsing expiration date in .trivyignore file: %s", err)
				continue
			}
		}
		ignoredFindings = append(ignoredFindings, IgnoreFinding{
			ID:        fields[0],
			ExpiredAt: exp,
		})
	}

	return ignoredFindings, nil
}

func getExpirationDate(fields []string) (time.Time, error) {
	for _, field := range fields {
		if strings.HasPrefix(field, "exp:") {
			return time.Parse("2006-01-02", strings.TrimPrefix(field, "exp:"))
		}
	}

	return time.Time{}, nil
}
