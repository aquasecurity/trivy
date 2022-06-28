package types

type LicenseType string

const (
	LicenseTypeDpkg LicenseType = "dpkg" // From /usr/share/doc/*/copyright
)

type LicenseFile struct {
	Type     LicenseType
	FilePath string
	Findings []LicenseFinding
	Layer    Layer  `json:",omitempty"`
	Package  string `json:"package,omitempty"`
}

type LicenseFinding struct {
	License                          string  `json:"license"`
	Confidence                       float64 `json:"match_confidence"`
	GoogleLicenseClassificationIndex int     `json:"classification_index"`
	GoogleLicenseClassification      string  `json:"google_license_classification"`
	LicenseLink                      string  `json:"license_link,omitempty"`
	PackageName                      string  `json:"package_name,omitempty"`
}

type PackageLicense struct {
	PackageName string
	Findings    []LicenseFinding
}
