package vex

import (
	"fmt"

	"github.com/openvex/discovery/pkg/discovery"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

type OCI struct{}

func NewOCI(report *types.Report) (*OpenVEX, error) {
	if report.ArtifactType != artifact.TypeContainerImage || len(report.Metadata.RepoDigests) == 0 {
		return nil, xerrors.New("'--vex oci' can be used only when scanning OCI artifacts stored in registries")
	}

	// TODO(knqyf263): Add the PURL field to Report.Metadata
	p, err := purl.New(purl.TypeOCI, report.Metadata, ftypes.Package{})
	if err != nil {
		return nil, xerrors.Errorf("failed to create a package URL: %w", err)
	}

	v, err := RetrieveVEXAttestation(p)
	if err != nil {
		return nil, xerrors.Errorf("failed to retrieve VEX attestation: %w", err)
	}
	return v, nil
}

func RetrieveVEXAttestation(p *purl.PackageURL) (*OpenVEX, error) {
	logger := log.WithPrefix("vex").With(log.String("type", "oci"),
		log.String("purl", p.String()))

	// Probe the OCI artifact and retrieve VEX documents
	vexDocuments, err := discovery.NewAgent().ProbePurl(p.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to probe the package URL: %w", err)
	}
	if len(vexDocuments) == 0 {
		logger.Info("No VEX attestations found")
		return nil, nil
	}

	logger.Debug("VEX attestation found, taking the first one")
	return &OpenVEX{
		vex:    *vexDocuments[0],
		source: fmt.Sprintf("VEX attestation in OCI registry (%s)", p.String()),
	}, nil
}
