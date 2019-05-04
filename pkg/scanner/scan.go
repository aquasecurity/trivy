package scanner

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/types"

	"github.com/knqyf263/trivy/pkg/scanner/ospkg"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

func ScanImage(imageName, filePath string, severities []vulnerability.Severity) ([]types.Vulnerability, error) {
	var err error
	ctx := context.Background()

	var files extractor.FileMap
	if imageName != "" {
		files, err = analyzer.Analyze(ctx, imageName)
		if err != nil {
			return nil, err
		}
	} else if filePath != "" {
		rc, err := openStream(filePath)
		if err != nil {
			return nil, err
		}

		files, err = analyzer.AnalyzeFromFile(ctx, rc)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, xerrors.New("image name or image file must be specified")
	}

	vulns, err := ospkg.Scan(files)
	if err != nil {
		return nil, err

	}

	var vulnerabilities []types.Vulnerability
	for _, vuln := range vulns {
		sev, title, err := getDetail(vuln.VulnerabilityID)
		if err != nil {
			return nil, err
		}

		// Filter vulnerabilities by severity
		for _, s := range severities {
			if s == sev {
				vuln.Severity = fmt.Sprint(sev)
				vuln.Title = title
				vulnerabilities = append(vulnerabilities, vuln)
				break
			}
		}
	}

	return vulnerabilities, nil
}

func openStream(path string) (*os.File, error) {
	if path == "-" {
		if terminal.IsTerminal(0) {
			flag.Usage()
			os.Exit(64)
		} else {
			return os.Stdin, nil
		}
	}
	return os.Open(path)
}

func getDetail(vulnID string) (vulnerability.Severity, string, error) {
	details, err := vulnerability.Get(vulnID)
	if err != nil {
		return vulnerability.SeverityUnknown, "", err
	}
	severity := getSeverity(details)
	title := getTitle(details)
	return severity, title, nil
}

func getSeverity(details map[string]vulnerability.Vulnerability) vulnerability.Severity {
	for _, source := range []string{vulnerability.Nvd, vulnerability.RedHat, vulnerability.Debian,
		vulnerability.DebianOVAL, vulnerability.Alpine} {
		d, ok := details[source]
		if !ok {
			continue
		}
		if d.Severity != 0 {
			return d.Severity
		} else if d.SeverityV3 != 0 {
			return d.SeverityV3
		} else if d.CvssScore > 0 {
			return scoreToSeverity(d.CvssScore)
		} else if d.CvssScoreV3 > 0 {
			return scoreToSeverity(d.CvssScoreV3)
		}
	}
	return vulnerability.SeverityUnknown
}

func getTitle(details map[string]vulnerability.Vulnerability) string {
	for _, source := range []string{vulnerability.Nvd, vulnerability.RedHat, vulnerability.Debian,
		vulnerability.DebianOVAL, vulnerability.Alpine} {
		d, ok := details[source]
		if !ok {
			continue
		}
		if d.Title != "" {
			return d.Title
		}
	}
	return ""
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
