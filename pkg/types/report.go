package types

import (
	"encoding/json"

	v1 "github.com/google/go-containerregistry/pkg/v1" // nolint: goimports

	ftypes "github.com/aquasecurity/fanal/types"
	gdpTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

// Report represents a scan result
type Report struct {
	SchemaVersion int                 `json:",omitempty"`
	ArtifactName  string              `json:",omitempty"`
	ArtifactType  ftypes.ArtifactType `json:",omitempty"`
	Metadata      Metadata            `json:",omitempty"`
	Results       Results             `json:",omitempty"`
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

const (
	ClassOSPkg   = "os-pkgs"
	ClassLangPkg = "lang-pkgs"
	ClassConfig  = "config"
	ClassSecret  = "secret"
)

// Result holds a target and detected vulnerabilities
type Result struct {
	Target            string                     `json:"Target"`
	Class             ResultClass                `json:"Class,omitempty"`
	Type              string                     `json:"Type,omitempty"`
	Packages          []ftypes.Package           `json:"Packages,omitempty"`
	Dependencies      []gdpTypes.Dependency      `json:"Dependencies,omitempty"`
	Vulnerabilities   []DetectedVulnerability    `json:"Vulnerabilities,omitempty"`
	MisconfSummary    *MisconfSummary            `json:"MisconfSummary,omitempty"`
	Misconfigurations []DetectedMisconfiguration `json:"Misconfigurations,omitempty"`
	Secrets           []ftypes.SecretFinding     `json:"Secrets,omitempty"`
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

type MisconfSummary struct {
	Successes  int
	Failures   int
	Exceptions int
}

func (s MisconfSummary) Empty() bool {
	return s.Successes == 0 && s.Failures == 0 && s.Exceptions == 0
}

// Failed returns whether the result includes any vulnerabilities or misconfigurations
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
	}
	return false
}
