package licensing

import (
	"fmt"
	"io"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/go-enry/go-license-detector/v4/licensedb"
	classifier "github.com/google/licenseclassifier/v2"
)

var LicenseClassifier Classifier

type Classifier struct {
	cf *classifier.Classifier
}

func NewClassifier() {
	LicenseClassifier = Classifier{cf: classifier.NewDefaultClassifier()}

	licensedb.Preload()
}

func (c Classifier) Match(in []byte) classifier.Results {
	return c.cf.Match(in)
}

func (c *Classifier) MatchFrom(in io.Reader) (classifier.Results, error) {
	return c.cf.MatchFrom(in)
}

func (c Classifier) Normalize(in []byte) []byte {
	return c.cf.Normalize(in)
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
	matcher := LicenseClassifier.Match(LicenseClassifier.Normalize(contents))
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
