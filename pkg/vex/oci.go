package vex

import (
	"fmt"

	"github.com/openvex/discovery/pkg/discovery"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

type OCI struct{}

func NewOCI(root *core.Component) (*OpenVEX, error) {
	if root == nil || root.PkgIdentifier.PURL == nil || root.PkgIdentifier.PURL.Type != packageurl.TypeOCI {
		return nil, xerrors.New("'--vex oci' can be used only when scanning OCI artifacts stored in registries")
	}
	logger := log.WithPrefix("vex").With(log.String("type", "oci"),
		log.String("purl", root.PkgIdentifier.PURL.String()))

	// Probe the OCI artifact and retrieve VEX documents
	vexDocuments, err := discovery.NewAgent().ProbePurl(root.PkgIdentifier.PURL.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to probe the package URL: %w", err)
	}
	if len(vexDocuments) == 0 {
		logger.Info("No VEX documents found")
		return nil, nil
	}

	logger.Debug("VEX document found, taking the first one")
	return &OpenVEX{
		vex:    *vexDocuments[0],
		source: fmt.Sprintf("VEX attestation in OCI registry (%s)", root.PkgIdentifier.PURL.String()),
	}, nil
}
