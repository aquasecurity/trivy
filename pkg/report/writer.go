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

type Metadata struct {
	Size int64      `json:",omitempty"`
	OS   *ftypes.OS `json:",omitempty"`

	// Container image
	RepoTags    []string `json:",omitempty"`
	RepoDigests []string `json:",omitempty"`
}

// Results to hold list of Result
type Results []Result

// Result holds a target and detected vulnerabilities
type Result struct {
	Target          string                        `json:"Target"`
	Type            string                        `json:"Type,omitempty"`
	Packages        []ftypes.Package              `json:"Packages,omitempty"`
	Vulnerabilities []types.DetectedVulnerability `json:"Vulnerabilities,omitempty"`
}

// Failed returns whether the result includes any vulnerabilities
func (results Results) Failed() bool {
	for _, r := range results {
		if len(r.Vulnerabilities) > 0 {
			return true
		}
	}
	return false
}

// Write writes the result to output, format as passed in argument
func Write(format string, output io.Writer, severities []dbTypes.Severity, report Report,
	outputTemplate string, light bool) error {
	var writer Writer
	switch format {
	case "table":
		writer = &TableWriter{Output: output, Light: light, Severities: severities}
	case "json":
		writer = &JSONWriter{Output: output}
	case "cyclonedx":
		writer = &CycloneDXWriter{Output: output}
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
