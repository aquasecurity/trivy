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
	License string `json:"license"`
}
