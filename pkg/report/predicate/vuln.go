package predicate

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"
	"io"
	"k8s.io/utils/clock"
	"time"
)

type CosignVulnPredicate struct {
	Invocation Invocation `json:"invocation"`
	Scanner    Scanner    `json:"scanner"`
	Metadata   Metadata   `json:"metadata"`
}

type Invocation struct {
	Parameters interface{} `json:"parameters"`
	URI        string      `json:"uri"`
	EventID    string      `json:"event_id"`
	BuilderID  string      `json:"builder.id"`
}

type DB struct {
	URI     string `json:"uri"`
	Version string `json:"version"`
}

type Scanner struct {
	URI     string       `json:"uri"`
	Version string       `json:"version"`
	DB      DB           `json:"db"`
	Result  types.Report `json:"result"`
}

type Metadata struct {
	ScanStartedOn  time.Time `json:"scanStartedOn"`
	ScanFinishedOn time.Time `json:"scanFinishedOn"`
}

type options struct {
	clock clock.Clock
}

type option func(*options)

func WithClock(clock clock.Clock) option {
	return func(opts *options) {
		opts.clock = clock
	}
}

type Writer struct {
	output  io.Writer
	version string
	*options
}

func NewWriter(output io.Writer, version string, opts ...option) Writer {
	o := &options{
		clock: clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}

	return Writer{
		output:  output,
		version: version,
		options: o,
	}
}

func (w Writer) Write(report types.Report) error {

	predicate := CosignVulnPredicate{}

	purl := packageurl.NewPackageURL("github", "aquasecurity", "trivy", w.version, nil, "")
	predicate.Scanner = Scanner{
		URI:     purl.ToString(),
		Version: w.version,
		Result:  report,
	}

	now := w.options.clock.Now()
	predicate.Metadata = Metadata{
		ScanStartedOn:  now,
		ScanFinishedOn: now,
	}

	output, err := json.MarshalIndent(predicate, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal cosign vulnerability predicate: %w", err)
	}

	if _, err = fmt.Fprint(w.output, string(output)); err != nil {
		return xerrors.Errorf("failed to write cosign vulnerability predicate: %w", err)
	}
	return nil

}
