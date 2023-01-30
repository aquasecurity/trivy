package types

import (
	"encoding/json"

	v1 "github.com/google/go-containerregistry/pkg/v1" // nolint: goimports

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var Compliances = []string{
	ComplianceK8sNsa,
	ComplianceK8sCIS,
	ComplianceK8sPSSBaseline,
	ComplianceK8sPSSRestricted,
	ComplianceAWSCIS12,
	ComplianceAWSCIS14,
	ComplianceDockerCIS,
}

// Report represents a scan result
type Report struct {
	SchemaVersion int                 `json:",omitempty"`
	ArtifactName  string              `json:",omitempty"`
	ArtifactType  ftypes.ArtifactType `json:",omitempty"`
	Metadata      Metadata            `json:",omitempty"`
	Results       Results             `json:",omitempty"`

	// SBOM
	CycloneDX *ftypes.CycloneDX `json:"-"` // Just for internal usage, not exported in JSON
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

const (
	ClassOSPkg       = "os-pkgs"      // For detected packages and vulnerabilities in OS packages
	ClassLangPkg     = "lang-pkgs"    // For detected packages and vulnerabilities in language-specific packages
	ClassConfig      = "config"       // For detected misconfigurations
	ClassSecret      = "secret"       // For detected secrets
	ClassLicense     = "license"      // For detected package licenses
	ClassLicenseFile = "license-file" // For detected licenses in files
	ClassCustom      = "custom"

	ComplianceK8sNsa           = Compliance("k8s-nsa")
	ComplianceK8sCIS           = Compliance("k8s-cis")
	ComplianceK8sPSSBaseline   = Compliance("k8s-pss-baseline")
	ComplianceK8sPSSRestricted = Compliance("k8s-pss-restricted")
	ComplianceAWSCIS12         = Compliance("aws-cis-1.2")
	ComplianceAWSCIS14         = Compliance("aws-cis-1.4")
	ComplianceDockerCIS        = Compliance("docker-cis")
)

// Result holds a target and detected vulnerabilities
type Result struct {
	Target            string                     `json:"Target"`
	Class             ResultClass                `json:"Class,omitempty"`
	Type              string                     `json:"Type,omitempty"`
	Packages          []ftypes.Package           `json:"Packages,omitempty"`
	Vulnerabilities   []DetectedVulnerability    `json:"Vulnerabilities,omitempty"`
	MisconfSummary    *MisconfSummary            `json:"MisconfSummary,omitempty"`
	Misconfigurations []DetectedMisconfiguration `json:"Misconfigurations,omitempty"`
	Secrets           []ftypes.SecretFinding     `json:"Secrets,omitempty"`
	Licenses          []DetectedLicense          `json:"Licenses,omitempty"`
	CustomResources   []ftypes.CustomResource    `json:"CustomResources,omitempty"`
}

func (r *Result) MarshalJSON() ([]byte, error) {
	// VendorSeverity includes all vendor severities.
	// It would be noisy to users, so it should be removed from the JSON output.
	for i := range r.Vulnerabilities {
		r.Vulnerabilities[i].VendorSeverity = nil
	}

	// remove the Highlighted attribute from the json results
	for i := range r.Misconfigurations {
		for li := range r.Misconfigurations[i].CauseMetadata.Code.Lines {
			r.Misconfigurations[i].CauseMetadata.Code.Lines[li].Highlighted = ""
		}
	}

	// Notice the Alias struct prevents MarshalJSON being called infinitely
	type ResultAlias Result
	return json.Marshal(&struct {
		*ResultAlias
	}{
		ResultAlias: (*ResultAlias)(r),
	})
}

func (r *Result) IsEmpty() bool {
	return len(r.Packages) == 0 && len(r.Vulnerabilities) == 0 && len(r.Misconfigurations) == 0 &&
		len(r.Secrets) == 0 && len(r.Licenses) == 0 && len(r.CustomResources) == 0
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
			if m.Status == StatusFailure {
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
