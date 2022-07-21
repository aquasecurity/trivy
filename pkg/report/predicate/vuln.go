package predicate

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/package-url/packageurl-go"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"golang.org/x/xerrors"
	"io"
	"time"
)

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

	predicate := attestation.CosignVulnPredicate{}

	var result map[string]interface{}
	reportJson, _ := json.Marshal(report)   // nolint: errcheck
	_ = json.Unmarshal(reportJson, &result) // nolint: errcheck

	purl := packageurl.NewPackageURL("github", "aquasecurity", "trivy", w.version, nil, "")
	predicate.Scanner = attestation.Scanner{
		URI:     purl.ToString(),
		Version: w.version,
		Result:  result,
	}

	now := time.Now()
	predicate.Metadata = attestation.Metadata{
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
