//go:build tinygo.wasm

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/module/wasm"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	ModuleVersion     = 1
	ModuleName        = "spring4shell"
	TypeJavaMajor     = ModuleName + "/java-major-version"
	TypeTomcatVersion = ModuleName + "/tomcat-version"
)

var (
	tomcatVersionRegex = regexp.MustCompile(`Apache Tomcat Version ([\d.]+)`)
)

// main is required for TinyGo to compile to Wasm.
func main() {
	wasm.RegisterModule(Spring4Shell{})
}

type Spring4Shell struct{}

func (Spring4Shell) Version() int {
	return ModuleVersion
}

func (Spring4Shell) Name() string {
	return ModuleName
}

func (Spring4Shell) RequiredFiles() []string {
	return []string{
		`\/openjdk-\d+\/release`, // For OpenJDK version
		`\/jdk\d+\/release`,      // For JDK version
		`tomcat\/RELEASE-NOTES`,  // For Tomcat version
	}
}

func (s Spring4Shell) Analyze(filePath string) (*serialize.AnalysisResult, error) {
	wasm.Info(fmt.Sprintf("analyzing %s...", filePath))
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	switch {
	case strings.HasSuffix(filePath, "/release"):
		return s.parseJavaRelease(f, filePath)
	case strings.HasSuffix(filePath, "/RELEASE-NOTES"):
		return s.parseTomcatReleaseNotes(f, filePath)
	}

	return nil, nil
}

// Parse a jdk release file like "/usr/local/openjdk-11/release"
func (Spring4Shell) parseJavaRelease(f *os.File, filePath string) (*serialize.AnalysisResult, error) {
	var javaVersion string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "JAVA_VERSION=") {
			continue
		}

		ss := strings.Split(line, "=")
		if len(ss) != 2 {
			return nil, fmt.Errorf("invalid java version: %s", line)
		}

		javaVersion = strings.Trim(ss[1], `"`)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &serialize.AnalysisResult{
		CustomResources: []serialize.CustomResource{
			{
				Type:     TypeJavaMajor,
				FilePath: filePath,
				Data:     javaVersion,
			},
		},
	}, nil
}

func (Spring4Shell) parseTomcatReleaseNotes(f *os.File, filePath string) (*serialize.AnalysisResult, error) {
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	m := tomcatVersionRegex.FindStringSubmatch(string(b))
	if len(m) != 2 {
		return nil, fmt.Errorf("unknown tomcat release notes format")
	}

	return &serialize.AnalysisResult{
		CustomResources: []serialize.CustomResource{
			{
				Type:     TypeTomcatVersion,
				FilePath: filePath,
				Data:     m[1],
			},
		},
	}, nil
}

func (Spring4Shell) PostScanSpec() serialize.PostScanSpec {
	return serialize.PostScanSpec{
		Action: api.ActionUpdate, // Update severity
		IDs:    []string{"CVE-2022-22965"},
	}
}

func (Spring4Shell) PostScan(results serialize.Results) (serialize.Results, error) {
	var javaMajorVersion int
	var tomcatVersion string
	for _, result := range results {
		if result.Class != types.ClassCustom {
			continue
		}

		for _, c := range result.CustomResources {
			if c.Type == TypeJavaMajor {
				v := c.Data.(string)
				ss := strings.Split(v, ".")
				if len(ss) == 0 || len(ss) < 2 {
					wasm.Warn("Invalid Java version: " + v)
					continue
				}

				ver := ss[0]
				if ver == "1" {
					ver = ss[1]
				}

				var err error
				javaMajorVersion, err = strconv.Atoi(ver)
				if err != nil {
					wasm.Warn("Invalid Java version: " + v)
					continue
				}
			} else if c.Type == TypeTomcatVersion {
				tomcatVersion = c.Data.(string)
			}
		}
	}

	wasm.Info(fmt.Sprintf("Java Version: %d, Tomcat Version: %s", javaMajorVersion, tomcatVersion))

	vulnerable := true
	// TODO: version comparison
	if tomcatVersion == "10.0.20" || tomcatVersion == "9.0.62" || tomcatVersion == "8.5.78" {
		vulnerable = false
	} else if javaMajorVersion <= 8 {
		vulnerable = false
	}

	for i, result := range results {
		for j, vuln := range result.Vulnerabilities {
			// Look up Spring4Shell
			if vuln.VulnerabilityID != "CVE-2022-22965" {
				continue
			}

			// If it doesn't satisfy any of requirements, the severity should be changed to LOW.
			if !strings.Contains(vuln.PkgPath, ".war") || !vulnerable {
				wasm.Info(fmt.Sprintf("change %s CVE-2022-22965 severity from CRITICAL to LOW", vuln.PkgName))
				results[i].Vulnerabilities[j].Severity = "LOW"
			}
		}
	}

	return results, nil
}
