package result

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samber/lo"
	"golang.org/x/exp/slices"
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

func (findings IgnoreFindings) Match(path, id string) bool {
	for _, finding := range findings {
		if len(finding.Paths) != 0 && !slices.Contains(finding.Paths, path) {
			continue
		}
		if id == finding.ID {
			return true
		}
	}
	return false
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
	t := clock.Now()
	fmt.Print(t)
	// Filter out expired ignore findings
	filterExpired := func(item IgnoreFinding, index int) bool {
		if item.ExpiredAt.IsZero() {
			return true
		}
		return !item.ExpiredAt.Before(clock.Now())
	}
	conf.Vulnerabilities = lo.Filter(conf.Vulnerabilities, filterExpired)
	conf.Misconfigurations = lo.Filter(conf.Misconfigurations, filterExpired)
	conf.Secrets = lo.Filter(conf.Secrets, filterExpired)
	conf.Licenses = lo.Filter(conf.Licenses, filterExpired)

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
			if !exp.IsZero() {
				now := time.Now()
				if exp.Before(now) {
					continue
				}
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
