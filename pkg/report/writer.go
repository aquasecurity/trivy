package report

import (
	"io"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
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
	AppVersion     string

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
			IncludeNonFailures: option.IncludeNonFailures,
			Trace:              option.Trace,
		}
	case "json":
		writer = &JSONWriter{Output: option.Output}
	case "template":
		// We keep `sarif.tpl` template working for backward compatibility for a while.
		if strings.HasPrefix(option.OutputTemplate, "@") && filepath.Base(option.OutputTemplate) == "sarif.tpl" {
			log.Logger.Warn("Using `--template sarif.tpl` is deprecated. Please migrate to `--format sarif`. See https://github.com/aquasecurity/trivy/discussions/1571")
			writer = SarifWriter{Output: option.Output, Version: option.AppVersion}
			break
		}
		var err error
		if writer, err = NewTemplateWriter(option.Output, option.OutputTemplate); err != nil {
			return xerrors.Errorf("failed to initialize template writer: %w", err)
		}
	case "sarif":
		writer = SarifWriter{Output: option.Output, Version: option.AppVersion}
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
