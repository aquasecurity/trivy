//go:generate tinygo build -o spring4shell.wasm -scheduler=none -target=wasi --no-debug spring4shell.go
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

type Spring4Shell struct {
	// Cannot define fields as modules can't keep state.
}

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

// PostScan takes results including custom resources and detected CVE-2022-22965.
//
// Example input:
// [
//
//	{
//	  "Target": "",
//	  "Class": "custom",
//	  "CustomResources": [
//	    {
//	      "Type": "spring4shell/java-major-version",
//	      "FilePath": "/usr/local/openjdk-8/release",
//	      "Layer": {
//	        "Digest": "sha256:d7b564a873af313eb2dbcb1ed0d393c57543e3666bdedcbe5d75841d72b1f791",
//	        "DiffID": "sha256:ba40706eccba610401e4942e29f50bdf36807f8638942ce20805b359ae3ac1c1"
//	      },
//	      "Data": "1.8.0_322"
//	    },
//	    {
//	      "Type": "spring4shell/tomcat-version",
//	      "FilePath": "/usr/local/tomcat/RELEASE-NOTES",
//	      "Layer": {
//	        "Digest": "sha256:59c0978ccb117247fd40d936973c40df89195f60466118c5acc6a55f8ba29f06",
//	        "DiffID": "sha256:85595543df2b1115a18284a8ef62d0b235c4bc29e3d33b55f89b54ee1eadf4c6"
//	      },
//	      "Data": "8.5.77"
//	    }
//	  ]
//	},
//	{
//	  "Target": "Java",
//	  "Class": "lang-pkgs",
//	  "Type": "jar",
//	  "Vulnerabilities": [
//	    {
//	      "VulnerabilityID": "CVE-2022-22965",
//	      "PkgName": "org.springframework.boot:spring-boot",
//	      "PkgPath": "usr/local/tomcat/webapps/helloworld.war",
//	      "InstalledVersion": "2.6.3",
//	      "FixedVersion": "2.5.12, 2.6.6",
//	      "Layer": {
//	        "Digest": "sha256:cc44af318e91e6f9f9bf73793fa4f0639487613f46aa1f819b02b6e8fb5c6c07",
//	        "DiffID": "sha256:eb769943b91f10a0418f2fc3b4a4fde6c6293be60c37293fcc0fa319edaf27a5"
//	      },
//	      "SeveritySource": "nvd",
//	      "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-22965",
//	      "DataSource": {
//	        "ID": "glad",
//	        "Name": "GitLab Advisory Database Community",
//	        "URL": "https://gitlab.com/gitlab-org/advisories-community"
//	      },
//	      "Title": "spring-framework: RCE via Data Binding on JDK 9+",
//	      "Description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
//	      "Severity": "CRITICAL",
//	      "CweIDs": [
//	        "CWE-94"
//	      ],
//	      "VendorSeverity": {
//	        "ghsa": 4,
//	        "nvd": 4,
//	        "redhat": 3
//	      },
//	      "CVSS": {
//	        "ghsa": {
//	          "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
//	          "V3Score": 9.8
//	        },
//	        "nvd": {
//	          "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
//	          "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
//	          "V2Score": 7.5,
//	          "V3Score": 9.8
//	        },
//	        "redhat": {
//	          "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
//	          "V3Score": 8.1
//	        }
//	      },
//	      "References": [
//	        "https://github.com/advisories/GHSA-36p3-wjmg-h94x"
//	      ],
//	      "PublishedDate": "2022-04-01T23:15:00Z",
//	      "LastModifiedDate": "2022-05-19T14:21:00Z"
//	    }
//	  ]
//	}
//
// ]
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
