package predicate

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"
	"io"
	"time"
)

// CosignVulnPredicate represents the Cosign Vulnerability Scan Record.
// Cosign provides the CosignVulnPredicate structure in their repository.
// But the type of Scanner.Result is defined as map[string]interface{}, which is difficult to use,
// so we define our own.
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

type Writer struct {
	output  io.Writer
	version string
}

func NewWriter(output io.Writer, version string) Writer {
	return Writer{
		output:  output,
		version: version,
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

	now := clock.Now()
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
