package library

import (
	"fmt"
	"os"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"golang.org/x/xerrors"

	"github.com/knqyf263/go-version"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/scanner/library/composer"
	"github.com/knqyf263/trivy/pkg/scanner/library/gem"
	"github.com/knqyf263/trivy/pkg/scanner/library/npm"
	"github.com/knqyf263/trivy/pkg/types"
	"github.com/knqyf263/trivy/pkg/vulnsrc/nvd"
)

type Scanner interface {
	UpdateDB() error
	ParseLockfile() ([]types.Library, error)
	Detect(string, *version.Version) ([]types.Vulnerability, error)
}

func Scan(f *os.File, severities []vulnerability.Severity) ([]types.Vulnerability, error) {
	var scanner Scanner
	switch f.Name() {
	case "Gemfile.lock":
		scanner = gem.NewScanner(f)
	case "composer.lock":
		scanner = composer.NewScanner(f)
	case "package-lock.json":
		scanner = npm.NewScanner(f)
	default:
		return nil, xerrors.New("unknown file type")
	}

	log.Logger.Info("Updating DB...")
	err := scanner.UpdateDB()
	if err != nil {
		return nil, err
	}

	pkgs, err := scanner.ParseLockfile()
	if err != nil {
		return nil, err
	}

	var vulnerabilities []types.Vulnerability
	for _, pkg := range pkgs {
		v, err := version.NewVersion(pkg.Version)
		if err != nil {
			log.Logger.Debug(err)
			continue
		}

		vulns, err := scanner.Detect(pkg.Name, v)
		if err != nil {
			return nil, err
		}
		for _, vuln := range vulns {
			severity := scoreToSeverity(vuln.Score)
			if severity == vulnerability.SeverityUnknown {
				s, err := getSeverity(vuln.VulnerabilityID)
				if err != nil {
					return nil, err
				}
				severity, _ = vulnerability.NewSeverity(s)
			}

			// Filter vulnerabilities by severity
			for _, s := range severities {
				if s == severity {
					vuln.Severity = fmt.Sprint(severity)
					vulnerabilities = append(vulnerabilities, vuln)
					break
				}
			}
		}
	}

	return vulnerabilities, nil
}

func getSeverity(vulnID string) (string, error) {
	nvdItem, err := nvd.Get(vulnID)
	if err != nil {
		return "", err
	}
	if nvdItem == nil {
		return fmt.Sprint(vulnerability.SeverityUnknown), nil
	}
	if nvdItem.Impact.BaseMetricV3.CvssV3.BaseSeverity == "" {
		return nvdItem.Impact.BaseMetricV2.Severity, nil
	}
	return nvdItem.Impact.BaseMetricV3.CvssV3.BaseSeverity, nil

}

func scoreToSeverity(score float64) vulnerability.Severity {
	if score >= 9.0 {
		return vulnerability.SeverityCritical
	} else if score >= 7.0 {
		return vulnerability.SeverityHigh
	} else if score >= 4.0 {
		return vulnerability.SeverityMedium
	} else if score > 0.0 {
		return vulnerability.SeverityLow
	}
	return vulnerability.SeverityUnknown
}
