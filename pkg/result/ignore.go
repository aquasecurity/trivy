package result

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
)

// IgnoreFinding represents an item to be ignored.
type IgnoreFinding struct {
	// ID is the identifier of the vulnerability, misconfiguration, secret, or license.
	// e.g. CVE-2019-8331, AVD-AWS-0175, etc.
	// required: true
	ID string `yaml:"id"`

	// Paths is the list of file paths to ignore.
	// If Paths is not set, the ignore finding is applied to all files.
	// required: false
	Paths []string `yaml:"paths"`

	// PURLs is the list of packages to ignore.
	// If PURLs is not set, the ignore finding is applied to packages.
	// The field is currently available only for vulnerabilities.
	// required: false
	PURLs []*purl.PackageURL `yaml:"-"` // Filled in UnmarshalYAML

	// ExpiredAt is the expiration date of the ignore finding.
	// If ExpiredAt is not set, the ignore finding is always valid.
	// required: false
	ExpiredAt time.Time `yaml:"expired_at"`

	// Statement describes the reason for ignoring the finding.
	// required: false
	Statement string `yaml:"statement"`

	// StartLine is the starting line of the ignore finding
	// required: false
	StartLine int `yaml:"start_line"`

	// EndLine is the end line of the ignore finding
	// required: false
	EndLine int `yaml:"end_line"`
}

// UnmarshalYAML is a custom unmarshaler for IgnoreFinding that handles
// the conversion of PURLs from strings to purl.PackageURL objects.
func (i *IgnoreFinding) UnmarshalYAML(value *yaml.Node) error {
	// Define a shadow type to prevent infinite recursion
	type plain IgnoreFinding
	var tmp struct {
		plain `yaml:",inline"`
		PURLs []string `yaml:"purls"`
	}
	if err := value.Decode(&tmp); err != nil {
		return err
	}

	*i = IgnoreFinding(tmp.plain)

	for _, pattern := range i.Paths {
		if !doublestar.ValidatePattern(pattern) {
			return xerrors.Errorf("invalid path pattern in the ignore file, id: %s, path: %s", i.ID, pattern)
		}
	}

	// Convert string PURLs to purl.PackageURL objects
	for _, purlStr := range tmp.PURLs {
		parsedPURL, err := purl.FromString(purlStr)
		if err != nil {
			return xerrors.Errorf("purl error in the ignore file: %w", err)
		}
		i.PURLs = append(i.PURLs, parsedPURL)
	}

	return nil
}

type IgnoreFindings []IgnoreFinding

func (f *IgnoreFindings) Match(id string, results *FindingsResults) *IgnoreFinding {
	for _, finding := range *f {
		if id != finding.ID {
			continue
		}
		if !matchPath(results.TargetPath, finding.Paths) || !matchPURL(results.PackageURL, finding.PURLs) {
			continue
		}

		if finding.StartLine != 0 && finding.EndLine != 0 &&
			(finding.StartLine != results.StartLine || finding.EndLine != results.EndLine) {
			continue
		}

		log.Debug("Ignored", log.String("id", id), log.String("target", results.TargetPath))

		if finding.StartLine > 0 || finding.EndLine > 0 {
			log.Debug("Ignored lines", log.String("start_line:end_line", fmt.Sprintf("%d:%d", results.StartLine, results.EndLine)))
		}

		return &finding
	}

	return nil
}

func matchPath(path string, patterns []string) bool {
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

func matchPURL(target *packageurl.PackageURL, purls []*purl.PackageURL) bool {
	if target == nil || len(purls) == 0 {
		return true
	}

	for _, p := range purls {
		if p.Match(target) {
			return true
		}
	}
	return false
}

func (f *IgnoreFindings) Prune(ctx context.Context) {
	var findings IgnoreFindings
	for _, finding := range *f {
		// Filter out expired ignore findings
		if !finding.ExpiredAt.IsZero() && finding.ExpiredAt.Before(clock.Now(ctx)) {
			continue
		}
		findings = append(findings, finding)
	}
	*f = findings
}

// IgnoreConfig represents the structure of .trivyignore.yaml.
type IgnoreConfig struct {
	FilePath          string
	Vulnerabilities   IgnoreFindings `yaml:"vulnerabilities"`
	Misconfigurations IgnoreFindings `yaml:"misconfigurations"`
	Secrets           IgnoreFindings `yaml:"secrets"`
	Licenses          IgnoreFindings `yaml:"licenses"`
}

func (c *IgnoreConfig) MatchVulnerability(vulnID, filePath, pkgPath string, pkg *packageurl.PackageURL) *IgnoreFinding {
	paths := []string{
		filePath,
		pkgPath,
	}

	for _, p := range paths {
		findingResults := &FindingsResults{
			IDS:        []string{vulnID},
			TargetPath: p,
			PackageURL: pkg,
		}

		if f := c.Vulnerabilities.Match(vulnID, findingResults); f != nil {
			return f
		}
	}
	return nil
}

func (c *IgnoreConfig) MatchMisconfiguration(results *FindingsResults) *IgnoreFinding {
	for _, id := range results.IDS {
		if f := c.Misconfigurations.Match(id, results); f != nil {
			return f
		}
	}
	return nil
}

func (c *IgnoreConfig) MatchSecret(secretID, filePath string) *IgnoreFinding {
	return c.Secrets.Match(secretID, &FindingsResults{TargetPath: filePath})
}

func (c *IgnoreConfig) MatchLicense(licenseID, filePath string) *IgnoreFinding {
	return c.Licenses.Match(licenseID, &FindingsResults{TargetPath: filePath})
}

func ParseIgnoreFile(ctx context.Context, ignoreFile string) (IgnoreConfig, error) {
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

	conf.Vulnerabilities.Prune(ctx)
	conf.Misconfigurations.Prune(ctx)
	conf.Secrets.Prune(ctx)
	conf.Licenses.Prune(ctx)
	conf.FilePath = filepath.ToSlash(filepath.Clean(ignoreFile))

	return conf, nil
}

func parseIgnoreYAML(ignoreFile string) (IgnoreConfig, error) {
	// Read .trivyignore.yaml
	f, err := os.Open(ignoreFile)
	if err != nil {
		return IgnoreConfig{}, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()
	log.Debug("Found an ignore yaml", log.FilePath(ignoreFile))

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
	log.Debug("Found an ignore file", log.FilePath(ignoreFile))

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
				log.Warn("Error while parsing expiration date in .trivyignore file", log.Err(err))
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
