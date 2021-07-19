package report

import (
	"io"
	"time"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	SchemaVersion = 2
)

// Now returns the current time
var Now = time.Now

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
			if m.Status == types.StatusFailure {
				return true
			}
		}
	}
	return false
}

type Option struct {
	Format         string
	Output         io.Writer
	Severities     []dbTypes.Severity
	OutputTemplate string
	Light          bool

	// For misconfigurations
	IncludeNonFailures bool
	Trace              bool
}

// Write writes the result to output, format as passed in argument
func Write(report Report, option Option) error {
	var writer Writer
	switch option.Format {
	case "table":
		writer = &TableWriter{
			Output:             option.Output,
			Severities:         option.Severities,
			Light:              option.Light,
			IncludeNonFailures: option.IncludeNonFailures,
			Trace:              option.Trace,
		}
	case "json":
		writer = &JSONWriter{Output: option.Output}
	case "template":
		var err error
		if writer, err = NewTemplateWriter(option.Output, option.OutputTemplate); err != nil {
			return xerrors.Errorf("failed to initialize template writer: %w", err)
		}
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
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
