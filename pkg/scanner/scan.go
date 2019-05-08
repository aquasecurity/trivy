package scanner

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/knqyf263/trivy/pkg/log"

	"github.com/knqyf263/trivy/pkg/report"

	"github.com/knqyf263/trivy/pkg/scanner/library"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/types"

	"github.com/knqyf263/trivy/pkg/scanner/ospkg"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

var (
	sources = []string{vulnerability.Nvd, vulnerability.RedHat, vulnerability.Debian,
		vulnerability.DebianOVAL, vulnerability.Alpine, vulnerability.RubySec, vulnerability.PhpSecurityAdvisories,
		vulnerability.NodejsSecurityWg, vulnerability.PythonSafetyDB}
)

func ScanImage(imageName, filePath string, severities []vulnerability.Severity, ignoreUnfixed bool) (report.Results, error) {
	var results report.Results
	var err error
	ctx := context.Background()

	var target string
	var files extractor.FileMap
	if imageName != "" {
		target = imageName
		files, err = analyzer.Analyze(ctx, imageName)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze image: %w", err)
		}
	} else if filePath != "" {
		target = filePath
		rc, err := openStream(filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open stream: %w", err)
		}

		files, err = analyzer.AnalyzeFromFile(ctx, rc)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, xerrors.New("image name or image file must be specified")
	}

	osFamily, osVersion, osVulns, err := ospkg.Scan(files)
	if err != nil {
		return nil, xerrors.New("failed to scan image")

	}

	results = append(results, report.Result{
		FileName:        fmt.Sprintf("%s (%s %s)", target, osFamily, osVersion),
		Vulnerabilities: processVulnerabilties(osVulns, severities, ignoreUnfixed),
	})

	libVulns, err := library.Scan(files)
	if err != nil {
		return nil, xerrors.New("failed to scan libraries")
	}
	for path, vulns := range libVulns {
		results = append(results, report.Result{
			FileName:        path,
			Vulnerabilities: processVulnerabilties(vulns, severities, ignoreUnfixed),
		})
	}

	return results, nil
}

func ScanFile(f *os.File, severities []vulnerability.Severity) (report.Result, error) {
	vulns, err := library.ScanFile(f)
	if err != nil {
		return report.Result{}, xerrors.New("failed to scan libraries in file")
	}
	result := report.Result{
		FileName:        f.Name(),
		Vulnerabilities: processVulnerabilties(vulns, severities, false),
	}
	return result, nil
}

func processVulnerabilties(vulns []types.Vulnerability, severities []vulnerability.Severity, ignoreUnfixed bool) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability
	for _, vuln := range vulns {
		sev, title := getDetail(vuln.VulnerabilityID)

		// Filter vulnerabilities by severity
		for _, s := range severities {
			if s == sev {
				vuln.Severity = fmt.Sprint(sev)
				vuln.Title = title

				// Ignore unfixed vulnerabilities
				if ignoreUnfixed && vuln.FixedVersion == "" {
					continue
				}
				vulnerabilities = append(vulnerabilities, vuln)
				break
			}
		}
	}
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if vulnerabilities[i].PkgName != vulnerabilities[j].PkgName {
			return vulnerabilities[i].PkgName < vulnerabilities[j].PkgName
		}
		return vulnerability.CompareSeverityString(vulnerabilities[j].Severity, vulnerabilities[i].Severity)
	})
	return vulnerabilities
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

func getDetail(vulnID string) (vulnerability.Severity, string) {
	details, err := vulnerability.Get(vulnID)
	if err != nil {
		log.Logger.Debug(err)
		return vulnerability.SeverityUnknown, ""
	} else if len(details) == 0 {
		return vulnerability.SeverityUnknown, ""
	}
	severity := getSeverity(details)
	title := getTitle(details)
	if title == "" {
		title = getDescription(details)
	}
	splittedTitle := strings.Split(title, " ")
	if len(splittedTitle) >= 12 {
		title = strings.Join(splittedTitle[:12], " ") + "..."
	}
	return severity, title
}

func getSeverity(details map[string]vulnerability.Vulnerability) vulnerability.Severity {
	for _, source := range sources {
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
	for _, source := range sources {
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

func getDescription(details map[string]vulnerability.Vulnerability) string {
	for _, source := range sources {
		d, ok := details[source]
		if !ok {
			continue
		}
		if d.Description != "" {
			return d.Description
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
