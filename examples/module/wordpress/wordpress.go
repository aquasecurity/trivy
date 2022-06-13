//go:build tinygo.wasm

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-version"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/module/wasm"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	moduleVersion = 1
	moduleName    = "wordpress"
	typeWPVersion = "wordpress-version"
)

// main is required for TinyGo to compile to Wasm.
func main() {
	wasm.RegisterModule(WordpressModule{})
}

type WordpressModule struct{}

func (WordpressModule) Version() int {
	return moduleVersion
}

func (WordpressModule) Name() string {
	return moduleName
}

func (WordpressModule) RequiredFiles() []string {
	return []string{
		`wp-includes\/version.php`,
	}
}

func (s WordpressModule) Analyze(filePath string) (*serialize.AnalysisResult, error) {
	f, err := os.Open(filePath) // e.g. filePath: /usr/src/wordpress/wp-includes/version.php
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var wpVersion string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "$wp_version") {
			continue
		}

		ss := strings.Split(line, "=")
		if len(ss) != 2 {
			return nil, fmt.Errorf("invalid wordpress version: %s", line)
		}

		// NOTE: it is an example; you actually need to handle comments, etc
		ss[1] = strings.TrimSpace(ss[1])
		wpVersion = strings.Trim(ss[1], `''";`)
		wasm.Info(fmt.Sprintf("WordPress Version: %s", wpVersion))
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return &serialize.AnalysisResult{
		CustomResources: []serialize.CustomResource{
			{
				Type:     typeWPVersion,
				FilePath: filePath,
				Data:     wpVersion,
			},
		},
	}, nil
}

func (WordpressModule) PostScanSpec() serialize.PostScanSpec {
	return serialize.PostScanSpec{
		Action: api.ActionInsert, // Add new vulnerabilities
	}
}

func (WordpressModule) PostScan(results serialize.Results) (serialize.Results, error) {
	wasm.Info("post scan")

	// https://wpscan.com/vulnerability/4cd46653-4470-40ff-8aac-318bee2f998d
	affectedVersion, err := version.NewConstraint(">=5.7, <5.7.2")
	if err != nil {
		return nil, err
	}

	var (
		vulnerable        bool
		wpPath, wpVersion string
	)
	for _, result := range results {
		if result.Class != types.ClassCustom {
			continue
		}

		for _, c := range result.CustomResources {
			if c.Type != typeWPVersion {
				continue
			}
			wpPath = c.FilePath
			wpVersion = c.Data.(string)
			wasm.Info(fmt.Sprintf("WordPress Version: %s", wpVersion))

			ver, err := version.NewVersion(wpVersion)
			if err != nil {
				return nil, err
			}
			if affectedVersion.Check(ver) {
				vulnerable = true
			}
			break
		}
	}

	if vulnerable {
		// Add CVE-2020-36326 and CVE-2018-19296
		results = append(results, serialize.Result{
			Target: wpPath,
			Class:  types.ClassLangPkg,
			Type:   "wordpress",
			Vulnerabilities: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-36326",
					PkgName:          "wordpress",
					InstalledVersion: wpVersion,
					FixedVersion:     "5.7.2",
					Vulnerability: dbTypes.Vulnerability{
						Title:    "PHPMailer 6.1.8 through 6.4.0 allows object injection through Phar Deserialization via addAttachment with a UNC pathname.",
						Severity: "CRITICAL",
					},
				},
				{
					VulnerabilityID:  "CVE-2018-19296",
					PkgName:          "wordpress",
					InstalledVersion: wpVersion,
					FixedVersion:     "5.7.2",
					Vulnerability: dbTypes.Vulnerability{
						Title:    "PHPMailer before 5.2.27 and 6.x before 6.0.6 is vulnerable to an object injection attack.",
						Severity: "HIGH",
					},
				},
			},
		})
	}

	return results, nil
}
