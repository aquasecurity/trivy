package unpackaged

import (
	"bytes"
	"context"
	"errors"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	sbomatt "github.com/aquasecurity/trivy/pkg/attestation/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom"
)

func init() {
	handler.RegisterPostHandlerInit(types.UnpackagedPostHandler, NewUnpackagedHandler)
}

const version = 1

type unpackagedHook struct {
	client sbomatt.Rekor
}

func NewUnpackagedHandler(opt artifact.Option) (handler.PostHandler, error) {
	c, err := sbomatt.NewRekor(opt.RekorURL)
	if err != nil {
		return nil, xerrors.Errorf("rekor client error: %w", err)
	}
	return unpackagedHook{
		client: c,
	}, nil
}

// Handle retrieves SBOM of unpackaged executable files in Rekor.
func (h unpackagedHook) Handle(ctx context.Context, res *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	for filePath, digest := range res.Digests {
		// Skip files installed by OS package managers.
		if slices.Contains(res.SystemInstalledFiles, filePath) {
			continue
		}

		// Retrieve SBOM from Rekor according to the file digest.
		raw, err := h.client.RetrieveSBOM(ctx, digest)
		if errors.Is(err, sbomatt.ErrNoSBOMAttestation) {
			continue
		} else if err != nil {
			return err
		}

		r := bytes.NewReader(raw)

		// Detect the SBOM format like CycloneDX, SPDX, etc.
		format, err := sbom.DetectFormat(r)
		if err != nil {
			return err
		}

		// Parse the fetched SBOM
		bom, err := sbom.Decode(bytes.NewReader(raw), format)
		if err != nil {
			return err
		}

		if len(bom.Applications) > 0 {
			log.Logger.Infof("Found SBOM attestation in Rekor: %s", filePath)
			// Take the first app since this SBOM should contain a single application.
			app := bom.Applications[0]
			app.FilePath = filePath // Use the original file path rather than the one in the SBOM.
			blob.Applications = append(blob.Applications, app)
		}
	}

	return nil
}

func (h unpackagedHook) Version() int {
	return version
}

func (h unpackagedHook) Type() types.HandlerType {
	return types.UnpackagedPostHandler
}

func (h unpackagedHook) Priority() int {
	return types.UnpackagedPostHandlerPriority
}
