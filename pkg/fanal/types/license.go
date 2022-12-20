package types

type LicenseType string

const (
	LicenseTypeDpkg   LicenseType = "dpkg"         // From /usr/share/doc/*/copyright
	LicenseTypeHeader LicenseType = "header"       // From file headers
	LicenseTypeFile   LicenseType = "license-file" // From LICENSE, COPYRIGHT, etc.
)

type LicenseCategory string

const (
	CategoryForbidden    LicenseCategory = "forbidden"
	CategoryRestricted   LicenseCategory = "restricted"
	CategoryReciprocal   LicenseCategory = "reciprocal"
	CategoryNotice       LicenseCategory = "notice"
	CategoryPermissive   LicenseCategory = "permissive"
	CategoryUnencumbered LicenseCategory = "unencumbered"
	CategoryUnknown      LicenseCategory = "unknown"
)

type LicenseFile struct {
	Type     LicenseType
	FilePath string
	PkgName  string
	Findings LicenseFindings
	Layer    Layer `json:",omitempty"`
}

type LicenseFindings []LicenseFinding

func (findings LicenseFindings) Len() int {
	return len(findings)
}

func (findings LicenseFindings) Swap(i, j int) {
	findings[i], findings[j] = findings[j], findings[i]
}

func (findings LicenseFindings) Less(i, j int) bool {
	return findings[i].Name < findings[j].Name
}

type LicenseFinding struct {
	Category   LicenseCategory // such as "forbidden"
	Name       string
	Confidence float64
	Link       string
}
