package licensing

import (
	"fmt"
	"log"

	"github.com/go-enry/go-license-detector/v4/licensedb"
	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var cf *classifier.Classifier

func NewClassifier() {
	var err error
	cf, err = assets.DefaultClassifier()
	if err != nil {
		// It never reaches here.
		log.Fatal(err)
	}

	licensedb.Preload()
}

// Classify detects and classifies the licensedFile found in a file
func Classify(filePath string, contents []byte) types.LicenseFile {
	licFile := googleClassifierLicense(filePath, contents)

	if len(licFile.Findings) == 0 {
		return fallbackClassifyLicense(filePath, contents)
	}

	return licFile
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

func fallbackClassifyLicense(filePath string, contents []byte) types.LicenseFile {
	license := types.LicenseFile{
		Type:     types.LicenseTypeFile,
		FilePath: filePath,
	}

	matcher := licensedb.InvestigateLicenseText(contents)
	for l, confidence := range matcher {
		licenseLink := fmt.Sprintf("https://spdx.org/licenses/%s.html", l)

		license.Findings = append(license.Findings, types.LicenseFinding{
			Name:       l,
			Confidence: float64(confidence),
			Link:       licenseLink,
		})
	}

	return license
}
