package predicate

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/types"
)

// CosignVulnPredicate represents the Cosign Vulnerability Scan Record.
// CosignVulnPredicate is based on structures in the Cosign repository.
// We defined them ourselves to reduce our dependence on the repository.
// cf. https://github.com/sigstore/cosign/blob/e0547cff64f98585a837a524ff77ff6b47ff5609/pkg/cosign/attestation/attestation.go#L45-L50
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

type VulnWriter struct {
	output  io.Writer
	version string
}

func NewVulnWriter(output io.Writer, version string) VulnWriter {
	return VulnWriter{
		output:  output,
		version: version,
	}
}

func (w VulnWriter) Write(report types.Report) error {

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
