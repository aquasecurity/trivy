package licensing

import (
	"fmt"
	"io"
	"sync"

	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var cf *classifier.Classifier
var classifierOnce sync.Once

func initGoogleClassifier() error {
	// Initialize the default classifier once.
	// This loading is expensive and should be called only when the license classification is needed.
	var err error
	classifierOnce.Do(func() {
		log.Logger.Debug("Loading the the default license classifier...")
		cf, err = assets.DefaultClassifier()
	})
	return err
}

// Classify uses a single classifier to detect and classify the license found in a file
func Classify(r io.Reader) ([]types.LicenseFinding, error) {
	if err := initGoogleClassifier(); err != nil {
		return nil, err
	}

	// Use 'github.com/google/licenseclassifier' to find licenses
	result, err := cf.MatchFrom(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to match licenses: %w", err)
	}

	var findings []types.LicenseFinding
	seen := map[string]struct{}{}
	for _, match := range result.Matches {
		if match.Confidence <= 0.9 {
			continue
		}

		if _, ok := seen[match.Name]; !ok {
			findings = append(findings, types.LicenseFinding{
				Name: match.Name,
			})
			seen[match.Name] = struct{}{}
		}
	}
	return findings, nil
}

// GoogleClassify uses two Google classifier to detect and classify the license found in a file
func GoogleClassify(filePath string, contents []byte) (types.LicenseFile, error) {
	if err := initGoogleClassifier(); err != nil {
		return types.LicenseFile{}, err
	}
	return googleClassifierLicense(filePath, contents), nil
}

func googleClassifierLicense(filePath string, contents []byte) types.LicenseFile {
	var matchType types.LicenseType
	var findings []types.LicenseFinding
	matcher := cf.Match(cf.Normalize(contents))
	for _, m := range matcher.Matches {
		switch m.MatchType {
		case "Header":
			matchType = types.LicenseTypeHeader
		case "License":
			matchType = types.LicenseTypeFile
		}
		licenseLink := fmt.Sprintf("https://spdx.org/licenses/%s.html", m.Name)

		findings = append(findings, types.LicenseFinding{
			Name:       m.Name,
			Confidence: m.Confidence,
			Link:       licenseLink,
		})
	}

	return types.LicenseFile{
		Type:     matchType,
		FilePath: filePath,
		Findings: findings,
	}
}
