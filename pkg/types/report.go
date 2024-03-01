package types

import (
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1" // nolint: goimports

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

// Report represents a scan result
type Report struct {
	SchemaVersion int                 `json:",omitempty"`
	CreatedAt     time.Time           `json:",omitempty"`
	ArtifactName  string              `json:",omitempty"`
	ArtifactType  ftypes.ArtifactType `json:",omitempty"`
	Metadata      Metadata            `json:",omitempty"`
	Results       Results             `json:",omitempty"`

	// parsed SBOM
	BOM *core.BOM `json:"-"` // Just for internal usage, not exported in JSON
}

// Metadata represents a metadata of artifact
type Metadata struct {
	Size int64      `json:",omitempty"`
	OS   *ftypes.OS `json:",omitempty"`

	// Container image
	ImageID     string        `json:",omitempty"`
	DiffIDs     []string      `json:",omitempty"`
	RepoTags    []string      `json:",omitempty"`
	RepoDigests []string      `json:",omitempty"`
	ImageConfig v1.ConfigFile `json:",omitempty"`
}

// Results to hold list of Result
type Results []Result

type ResultClass string
type Compliance = string
type Format string

const (
	ClassUnknown     ResultClass = "unknown"
	ClassOSPkg       ResultClass = "os-pkgs"      // For detected packages and vulnerabilities in OS packages
	ClassLangPkg     ResultClass = "lang-pkgs"    // For detected packages and vulnerabilities in language-specific packages
	ClassConfig      ResultClass = "config"       // For detected misconfigurations
	ClassSecret      ResultClass = "secret"       // For detected secrets
	ClassLicense     ResultClass = "license"      // For detected package licenses
	ClassLicenseFile ResultClass = "license-file" // For detected licenses in files
	ClassCustom      ResultClass = "custom"

	ComplianceK8sNsa           = Compliance("k8s-nsa")
	ComplianceK8sCIS           = Compliance("k8s-cis")
	ComplianceK8sPSSBaseline   = Compliance("k8s-pss-baseline")
	ComplianceK8sPSSRestricted = Compliance("k8s-pss-restricted")
	ComplianceAWSCIS12         = Compliance("aws-cis-1.2")
	ComplianceAWSCIS14         = Compliance("aws-cis-1.4")
	ComplianceDockerCIS        = Compliance("docker-cis")

	FormatTable      Format = "table"
	FormatJSON       Format = "json"
	FormatTemplate   Format = "template"
	FormatSarif      Format = "sarif"
	FormatCycloneDX  Format = "cyclonedx"
	FormatSPDX       Format = "spdx"
	FormatSPDXJSON   Format = "spdx-json"
	FormatGitHub     Format = "github"
	FormatCosignVuln Format = "cosign-vuln"
)

var (
	SupportedFormats = []Format{
		FormatTable,
		FormatJSON,
		FormatTemplate,
		FormatSarif,
		FormatCycloneDX,
		FormatSPDX,
		FormatSPDXJSON,
		FormatGitHub,
		FormatCosignVuln,
	}
	SupportedSBOMFormats = []Format{
		FormatCycloneDX,
		FormatSPDX,
		FormatSPDXJSON,
		FormatGitHub,
	}
	SupportedCompliances = []string{
		ComplianceK8sNsa,
		ComplianceK8sCIS,
		ComplianceK8sPSSBaseline,
		ComplianceK8sPSSRestricted,
		ComplianceAWSCIS12,
		ComplianceAWSCIS14,
		ComplianceDockerCIS,
	}
)

// Result holds a target and detected vulnerabilities
type Result struct {
	Target            string                     `json:"Target"`
	Class             ResultClass                `json:"Class,omitempty"`
	Type              ftypes.TargetType          `json:"Type,omitempty"`
	Packages          []ftypes.Package           `json:"Packages,omitempty"`
	Vulnerabilities   []DetectedVulnerability    `json:"Vulnerabilities,omitempty"`
	MisconfSummary    *MisconfSummary            `json:"MisconfSummary,omitempty"`
	Misconfigurations []DetectedMisconfiguration `json:"Misconfigurations,omitempty"`
	Secrets           []DetectedSecret           `json:"Secrets,omitempty"`
	Licenses          []DetectedLicense          `json:"Licenses,omitempty"`
	CustomResources   []ftypes.CustomResource    `json:"CustomResources,omitempty"`

	// ModifiedFindings holds a list of findings that have been modified from their original state.
	// This can include vulnerabilities that have been marked as ignored, not affected, or have had
	// their severity adjusted. It is currently available only in the table format.
	ModifiedFindings []ModifiedFinding `json:"-"`
}

func (r *Result) IsEmpty() bool {
	return len(r.Packages) == 0 && len(r.Vulnerabilities) == 0 && len(r.Misconfigurations) == 0 &&
		len(r.Secrets) == 0 && len(r.Licenses) == 0 && len(r.CustomResources) == 0 && len(r.ModifiedFindings) == 0
}

type MisconfSummary struct {
	Successes  int
	Failures   int
	Exceptions int
}

func (s MisconfSummary) Empty() bool {
	return s.Successes == 0 && s.Failures == 0 && s.Exceptions == 0
}

// Failed returns whether the result includes any vulnerabilities, misconfigurations or secrets
func (results Results) Failed() bool {
	for _, r := range results {
		if len(r.Vulnerabilities) > 0 {
			return true
		}
		for _, m := range r.Misconfigurations {
			if m.Status == MisconfStatusFailure {
				return true
			}
		}
		if len(r.Secrets) > 0 {
			return true
		}
		if len(r.Licenses) > 0 {
			return true
		}
	}
	return false
}
