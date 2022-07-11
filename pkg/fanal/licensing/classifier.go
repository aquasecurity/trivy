package licensing

import (
	"fmt"

	"github.com/go-enry/go-license-detector/v4/licensedb"
	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type Classifier struct {
	classifier *classifier.Classifier
}

func NewClassifier() (*Classifier, error) {
	licensedb.Preload()

	c, err := assets.DefaultClassifier()
	if err != nil {
		return nil, err
	}
	return &Classifier{
		classifier: c,
	}, nil
}

// Classify detects and classifies the licensedFile found in a file
func (c *Classifier) Classify(filePath string, contents []byte) types.LicenseFile {
	licFile := c.googleClassifierLicense(filePath, contents)

	if len(licFile.Findings) == 0 {
		return c.fallbackClassifyLicense(filePath, contents)
	}

	return licFile
}

func (c *Classifier) googleClassifierLicense(filePath string, contents []byte) types.LicenseFile {
	license := types.LicenseFile{FilePath: filePath}
	matcher := c.classifier.Match(c.classifier.Normalize(contents))

	for _, m := range matcher.Matches {
		licenseLink := fmt.Sprintf("https://spdx.org/licenses/%s.html", m.Name)

		license.Findings = append(license.Findings, types.LicenseFinding{
			License:     m.Name,
			Confidence:  m.Confidence,
			LicenseLink: licenseLink,
		})
	}

	return license
}

func (c *Classifier) fallbackClassifyLicense(filePath string, contents []byte) types.LicenseFile {
	license := types.LicenseFile{FilePath: filePath}

	matcher := licensedb.InvestigateLicenseText(contents)
	for l, confidence := range matcher {
		licenseLink := fmt.Sprintf("https://spdx.org/licenses/%s.html", l)

		license.Findings = append(license.Findings, types.LicenseFinding{
			License:     l,
			Confidence:  float64(confidence),
			LicenseLink: licenseLink,
		})
	}

	return license
}
