package classification

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/go-enry/go-license-detector/v4/licensedb"
	"github.com/google/licenseclassifier"
	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/exp/slices"
)

var (
	IgnoredLicenses []string
)

type Classifier struct {
	classifier *classifier.Classifier
}

func NewClassifier(ignoredLicenses []string) (*Classifier, error) {
	var c *classifier.Classifier
	IgnoredLicenses = ignoredLicenses

	licensedb.Preload()

	_, err := assets.ReadLicenseDir()
	if err != nil {
		return nil, err
	}
	c, err = assets.DefaultClassifier()
	if err != nil {
		return nil, err
	}
	return &Classifier{
		classifier: c,
	}, nil
}

// Classify detects and classifies the licensedFile found in a file
func (c *Classifier) Classify(filePath string, contents []byte) (types.LicenseFile, error) {
	// licFile, err := c.defaultClassifyLicense(filePath, contents)
	// if err != nil {
	// 	return licFile, err
	// }
	//
	// if len(licFile.Findings) == 0 {
	// 	return c.googleClassifierLicense(filePath, contents)
	// }
	//
	// return licFile, nil

	return c.googleClassifierLicense(filePath, contents)
}

func (c *Classifier) googleClassifierLicense(filePath string, contents []byte) (types.LicenseFile, error) {

	license := types.LicenseFile{FilePath: filePath}
	matcher := c.classifier.Match(c.classifier.Normalize(contents))

	for _, m := range matcher.Matches {
		riskLevel, classification := GoogleClassification(m.Name)
		licenseLink := fmt.Sprintf("https://spdx.org/licenses/%s.html", m.Name)

		license.Findings = append(license.Findings, types.LicenseFinding{
			License:                          m.Name,
			Confidence:                       m.Confidence,
			GoogleLicenseClassificationIndex: riskLevel,
			GoogleLicenseClassification:      classification,
			LicenseLink:                      licenseLink,
		})
	}

	return license, nil
}

func (c *Classifier) defaultClassifyLicense(filePath string, contents []byte) (types.LicenseFile, error) {
	license := types.LicenseFile{FilePath: filePath}

	matcher := licensedb.InvestigateLicenseText(contents)
	for l, confidence := range matcher {
		riskLevel, classification := GoogleClassification(l)
		licenseLink := fmt.Sprintf("https://spdx.org/licenses/%s.html", l)

		license.Findings = append(license.Findings, types.LicenseFinding{
			License:                          l,
			Confidence:                       float64(confidence),
			GoogleLicenseClassificationIndex: riskLevel,
			GoogleLicenseClassification:      classification,
			LicenseLink:                      licenseLink,
		})
	}

	return license, nil
}

func GoogleClassification(licenseName string) (int, string) {

	switch licenseclassifier.LicenseType(licenseName) {
	case "unencumbered":
		return 7, "unencumbered"
	case "permissive":
		return 6, "permissive"
	case "notice":
		return 5, "notice"
	case "reciprocal":
		return 4, "reciprocal"
	case "restricted":
		return 3, "restricted"
	case "FORBIDDEN":
		return 2, "forbidden"
	default:
		return 1, "unknown"
	}
}

func LicenseIgnored(licenseName string) bool {
	if licenseName == "" {
		return true
	}

	if len(IgnoredLicenses) > 0 {
		return slices.Contains(IgnoredLicenses, licenseName)
	}

	return false
}
