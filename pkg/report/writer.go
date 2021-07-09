package report

import (
	"io"
	"time"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Now returns the current time
var Now = time.Now

// Report represents a scan result
type Report struct {
	ArtifactName string              `json:",omitempty"`
	ArtifactID   string              `json:",omitempty"`
	ArtifactType ftypes.ArtifactType `json:",omitempty"`
	Metadata     Metadata            `json:",omitempty"`
	Results      Results             `json:",omitempty"`
}

// Metadata represents a metadata of artifact
type Metadata struct {
	Size int64      `json:",omitempty"`
	OS   *ftypes.OS `json:",omitempty"`

	// Container image
	RepoTags    []string `json:",omitempty"`
	RepoDigests []string `json:",omitempty"`
}

// Results to hold list of Result
type Results []Result

type ResultClass string

const (
	ClassOSPkg   = "os-pkgs"
	ClassLangPkg = "lang-pkgs"
	ClassConfig  = "config"
)

// Result holds a target and detected vulnerabilities
type Result struct {
	Target            string                           `json:"Target"`
	Class             ResultClass                      `json:"Class,omitempty"`
	Type              string                           `json:"Type,omitempty"`
	Packages          []ftypes.Package                 `json:"Packages,omitempty"`
	Vulnerabilities   []types.DetectedVulnerability    `json:"Vulnerabilities,omitempty"`
	MisconfSummary    *MisconfSummary                  `json:"MisconfSummary,omitempty"`
	Misconfigurations []types.DetectedMisconfiguration `json:"Misconfigurations,omitempty"`
}

type MisconfSummary struct {
	Successes  int
	Failures   int
	Exceptions int
}

// Failed returns whether the result includes any vulnerabilities or misconfigurations
func (results Results) Failed() bool {
	for _, r := range results {
		if len(r.Vulnerabilities) > 0 {
			return true
		}
		for _, m := range r.Misconfigurations {
			if m.Status == types.StatusFailure {
				return true
			}
		}
	}
	return false
}

// Write writes the result to output, format as passed in argument
func Write(format string, output io.Writer, severities []dbTypes.Severity, report Report,
	outputTemplate string, light, includeSuccesses bool) error {
	var writer Writer
	switch format {
	case "table":
		writer = &TableWriter{
			Output:           output,
			Severities:       severities,
			Light:            light,
			IncludeSuccesses: includeSuccesses,
		}
	case "json":
		writer = &JSONWriter{Output: output}
	case "template":
		var err error
		if writer, err = NewTemplateWriter(output, outputTemplate); err != nil {
			return xerrors.Errorf("failed to initialize template writer: %w", err)
		}
	default:
		return xerrors.Errorf("unknown format: %v", format)
	}

	if err := writer.Write(report); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}
	return nil
}

// Writer defines the result write operation
type Writer interface {
	Write(Report) error
}
