package types

import (
	"encoding/json"

	"github.com/samber/lo"
)

type LicenseType string

const (
	LicenseTypeDpkg         LicenseType = "dpkg"          // From /usr/share/doc/*/copyright
	LicenseTypeHeader       LicenseType = "header"        // From file headers
	LicenseTypeFile         LicenseType = "license-file"  // From LICENSE, COPYRIGHT, etc.
	LicenseTypeName         LicenseType = "license-name"  // license name or expression
	LicenseTypeNonSeparable LicenseType = "non-separable" // text of license without possible to split
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

func (findings LicenseFindings) Names() []License {
	return lo.Map(findings, func(finding LicenseFinding, _ int) License {
		return License{
			Type:  LicenseTypeName,
			Value: finding.Name,
		}
	})
}

type LicenseFinding struct {
	Category   LicenseCategory // such as "forbidden"
	Name       string
	Confidence float64
	Link       string
}

type License struct {
	Type  LicenseType `json:",omitempty"`
	Value string      `json:",omitempty"`
}

type Licenses []License

func (ll *Licenses) ToStringSlice() []string {
	// TODO check type:
	// don't return files?
	// limit size of non-separable license
	return lo.Map(*ll, func(l License, _ int) string {
		return l.Value
	})
}

func NewLicense(typ, value string) License {
	var licenseType LicenseType
	switch typ {
	case string(LicenseTypeDpkg):
		licenseType = LicenseTypeDpkg
	case string(LicenseTypeHeader):
		licenseType = LicenseTypeHeader
	case string(LicenseTypeFile):
		licenseType = LicenseTypeFile
	case string(LicenseTypeName):
		licenseType = LicenseTypeName
	case string(LicenseTypeNonSeparable):
		licenseType = LicenseTypeNonSeparable
	}
	return License{
		Type:  licenseType,
		Value: value,
	}
}

// MarshalJSON customizes the JSON encoding of Licenses.
func (ll *Licenses) MarshalJSON() ([]byte, error) {
	return json.Marshal(ll.ToStringSlice())
}

// UnmarshalJSON customizes the JSON decoding of License.
func (ll *Licenses) UnmarshalJSON(data []byte) error {
	var stringLicenses []string
	if err := json.Unmarshal(data, &stringLicenses); err != nil {
		return err
	}
	licenses := Licenses{}
	for _, l := range stringLicenses {
		licenses = append(licenses, License{
			Type:  LicenseTypeName,
			Value: l,
		})
	}

	*ll = licenses
	return nil
}
