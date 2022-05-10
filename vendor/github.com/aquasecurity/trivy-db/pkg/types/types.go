package types

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

type Severity int

type VendorSeverity map[SourceID]Severity

type CVSS struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

type CVSSVector struct {
	V2 string `json:"v2,omitempty"`
	V3 string `json:"v3,omitempty"`
}

type VendorCVSS map[SourceID]CVSS

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var (
	SeverityNames = []string{
		"UNKNOWN",
		"LOW",
		"MEDIUM",
		"HIGH",
		"CRITICAL",
	}
	SeverityColor = []func(a ...interface{}) string{
		color.New(color.FgCyan).SprintFunc(),
		color.New(color.FgBlue).SprintFunc(),
		color.New(color.FgYellow).SprintFunc(),
		color.New(color.FgHiRed).SprintFunc(),
		color.New(color.FgRed).SprintFunc(),
	}
)

func NewSeverity(severity string) (Severity, error) {
	for i, name := range SeverityNames {
		if severity == name {
			return Severity(i), nil
		}
	}
	return SeverityUnknown, fmt.Errorf("unknown severity: %s", severity)
}

func CompareSeverityString(sev1, sev2 string) int {
	s1, _ := NewSeverity(sev1)
	s2, _ := NewSeverity(sev2)
	return int(s2) - int(s1)
}

func ColorizeSeverity(severity string) string {
	for i, name := range SeverityNames {
		if severity == name {
			return SeverityColor[i](severity)
		}
	}
	return color.New(color.FgBlue).SprintFunc()(severity)
}

func (s Severity) String() string {
	return SeverityNames[s]
}

type LastUpdated struct {
	Date time.Time
}
type VulnerabilityDetail struct {
	ID               string     `json:",omitempty"` // e.g. CVE-2019-8331, OSVDB-104365
	CvssScore        float64    `json:",omitempty"`
	CvssVector       string     `json:",omitempty"`
	CvssScoreV3      float64    `json:",omitempty"`
	CvssVectorV3     string     `json:",omitempty"`
	Severity         Severity   `json:",omitempty"`
	SeverityV3       Severity   `json:",omitempty"`
	CweIDs           []string   `json:",omitempty"` // e.g. CWE-78, CWE-89
	References       []string   `json:",omitempty"`
	Title            string     `json:",omitempty"`
	Description      string     `json:",omitempty"`
	PublishedDate    *time.Time `json:",omitempty"` // Take from NVD
	LastModifiedDate *time.Time `json:",omitempty"` // Take from NVD
}

type AdvisoryDetail struct {
	PlatformName string
	PackageName  string
	AdvisoryItem interface{}
}

// SourceID represents data source such as NVD.
type SourceID string

type DataSource struct {
	ID   SourceID `json:",omitempty"`
	Name string   `json:",omitempty"`
	URL  string   `json:",omitempty"`
}

type Advisory struct {
	VulnerabilityID string   `json:",omitempty"` // CVE-ID or vendor ID
	VendorIDs       []string `json:",omitempty"` // e.g. RHSA-ID and DSA-ID

	// It is filled only when FixedVersion is empty since it is obvious the state is "Fixed" when FixedVersion is not empty.
	// e.g. Will not fix and Affected
	State string `json:",omitempty"`

	// Trivy DB has "vulnerability" bucket and severities are usually stored in the bucket per a vulnerability ID.
	// In some cases, the advisory may have multiple severities depending on the packages.
	// For example, CVE-2015-2328 in Debian has "unimportant" for mongodb and "low" for pcre3.
	// e.g. https://security-tracker.debian.org/tracker/CVE-2015-2328
	Severity Severity `json:",omitempty"`

	// Versions for os package
	FixedVersion    string `json:",omitempty"`
	AffectedVersion string `json:",omitempty"` // Only for Arch Linux

	// MajorVersion ranges for language-specific package
	// Some advisories provide VulnerableVersions only, others provide PatchedVersions and UnaffectedVersions
	VulnerableVersions []string `json:",omitempty"`
	PatchedVersions    []string `json:",omitempty"`
	UnaffectedVersions []string `json:",omitempty"`

	// DataSource holds where the advisory comes from
	DataSource *DataSource `json:",omitempty"`

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom interface{} `json:",omitempty"`
}

type Vulnerability struct {
	Title            string         `json:",omitempty"`
	Description      string         `json:",omitempty"`
	Severity         string         `json:",omitempty"` // Selected from VendorSeverity, depending on a scan target
	CweIDs           []string       `json:",omitempty"` // e.g. CWE-78, CWE-89
	VendorSeverity   VendorSeverity `json:",omitempty"`
	CVSS             VendorCVSS     `json:",omitempty"`
	References       []string       `json:",omitempty"`
	PublishedDate    *time.Time     `json:",omitempty"` // Take from NVD
	LastModifiedDate *time.Time     `json:",omitempty"` // Take from NVD

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom interface{} `json:",omitempty"`
}

// Ecosystem represents language-specific ecosystem
type Ecosystem string
