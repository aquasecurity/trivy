package serialize

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type StringSlice []string

type AnalysisResult struct {
	// TODO: support other fields as well
	// OS                   *types.OS
	// Repository           *types.Repository
	// PackageInfos         []types.PackageInfo
	// Applications         []types.Application
	// Secrets              []types.Secret
	// SystemInstalledFiles []string // A list of files installed by OS package manager

	// Currently it supports custom resources only
	CustomResources []CustomResource
}

type CustomResource struct {
	Type     string
	FilePath string
	Data     any
}

type PostScanAction string

type PostScanSpec struct {
	// What action the module will do in post scanning.
	// value: INSERT, UPDATE and DELETE
	Action PostScanAction

	// IDs represent which vulnerability and misconfiguration ID will be updated or deleted in post scanning.
	// When the action is UPDATE, the matched result will be passed to the module.
	IDs []string
}

type Results []Result

// Result re-defines the Result struct from 'pkg/types/' so TinyGo can compile the code.
// See https://github.com/aquasecurity/trivy/issues/6654 for more details.
type Result struct {
	Target          string                  `json:"Target"`
	Class           string                  `json:"Class,omitempty"`
	Type            string                  `json:"Type,omitempty"`
	Vulnerabilities []DetectedVulnerability `json:"Vulnerabilities,omitempty"`
	CustomResources []CustomResource        `json:"CustomResources,omitempty"`
}

type DetectedVulnerability struct {
	VulnerabilityID  string         `json:",omitempty"`
	VendorIDs        []string       `json:",omitempty"`
	PkgID            string         `json:",omitempty"`
	PkgName          string         `json:",omitempty"`
	PkgPath          string         `json:",omitempty"`
	InstalledVersion string         `json:",omitempty"`
	FixedVersion     string         `json:",omitempty"`
	Status           types.Status   `json:",omitempty"`
	Layer            Layer          `json:",omitempty"`
	SeveritySource   types.SourceID `json:",omitempty"`
	PrimaryURL       string         `json:",omitempty"`

	// DataSource holds where the advisory comes from
	DataSource *types.DataSource `json:",omitempty"`

	// Custom is for extensibility and not supposed to be used in OSS
	Custom any `json:",omitempty"`

	// Embed vulnerability details
	types.Vulnerability
}

type DetectedMisconfiguration struct {
	Type          string        `json:",omitempty"`
	ID            string        `json:",omitempty"`
	AVDID         string        `json:",omitempty"`
	Title         string        `json:",omitempty"`
	Description   string        `json:",omitempty"`
	Message       string        `json:",omitempty"`
	Namespace     string        `json:",omitempty"`
	Query         string        `json:",omitempty"`
	Resolution    string        `json:",omitempty"`
	Severity      string        `json:",omitempty"`
	PrimaryURL    string        `json:",omitempty"`
	References    []string      `json:",omitempty"`
	Status        string        `json:",omitempty"`
	Layer         Layer         `json:",omitempty"`
	CauseMetadata CauseMetadata `json:",omitempty"`

	// For debugging
	Traces []string `json:",omitempty"`
}

type CauseMetadata struct {
	Resource    string       `json:",omitempty"`
	Provider    string       `json:",omitempty"`
	Service     string       `json:",omitempty"`
	StartLine   int          `json:",omitempty"`
	EndLine     int          `json:",omitempty"`
	Code        Code         `json:",omitempty"`
	Occurrences []Occurrence `json:",omitempty"`
}

type Occurrence struct {
	Resource string `json:",omitempty"`
	Filename string `json:",omitempty"`
	Location Location
}

type Location struct {
	StartLine int `json:",omitempty"`
	EndLine   int `json:",omitempty"`
}

type Code struct {
	Lines []Line
}

type Line struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation"`
	Truncated   bool   `json:"Truncated"`
	Highlighted string `json:"Highlighted,omitempty"`
	FirstCause  bool   `json:"FirstCause"`
	LastCause   bool   `json:"LastCause"`
}

type Layer struct {
	Digest    string `json:",omitempty"`
	DiffID    string `json:",omitempty"`
	CreatedBy string `json:",omitempty"`
}
