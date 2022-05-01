package spdx

import (
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/spdx/tools-golang/jsonsaver"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tvsaver"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	SPDXVersion         = "SPDX-2.2"
	DataLicense         = "CC0-1.0"
	SPDXIdentifier      = "DOCUMENT"
	DocumentNamespace   = "http://aquasecurity.github.io/trivy"
	CreatorOrganization = "aquasecurity"
	CreatorTool         = "trivy"
)

type Writer struct {
	output  io.Writer
	version string
	*options
}

type newUUID func() uuid.UUID

type options struct {
	format     spdx.Document2_1
	clock      clock.Clock
	newUUID    newUUID
	spdxFormat string
}

type option func(*options)

type spdxSaveFunction func(*spdx.Document2_2, io.Writer) error

func WithClock(clock clock.Clock) option {
	return func(opts *options) {
		opts.clock = clock
	}
}

func WithNewUUID(newUUID newUUID) option {
	return func(opts *options) {
		opts.newUUID = newUUID
	}
}

func NewWriter(output io.Writer, version string, spdxFormat string, opts ...option) Writer {
	o := &options{
		format:     spdx.Document2_1{},
		clock:      clock.RealClock{},
		newUUID:    uuid.New,
		spdxFormat: spdxFormat,
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

func (cw Writer) Write(report types.Report) error {
	spdxDoc, err := cw.convertToBom(report, cw.version)
	if err != nil {
		return xerrors.Errorf("failed to convert bom: %w", err)
	}

	var saveFunc spdxSaveFunction
	if cw.spdxFormat != "spdx-json" {
		saveFunc = tvsaver.Save2_2
	} else {
		saveFunc = jsonsaver.Save2_2
	}

	if err = saveFunc(spdxDoc, cw.output); err != nil {
		return xerrors.Errorf("failed to save bom: %w", err)
	}
	return nil
}

func (cw *Writer) convertToBom(r types.Report, version string) (*spdx.Document2_2, error) {
	packages := make(map[spdx.ElementID]*spdx.Package2_2)

	for _, result := range r.Results {
		for _, pkg := range result.Packages {
			spdxPackage, err := pkgToSpdxPackage(result.Type, r.Metadata, pkg)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse pkg: %w", err)
			}
			packages[spdxPackage.PackageSPDXIdentifier] = &spdxPackage
		}
	}

	return &spdx.Document2_2{
		CreationInfo: &spdx.CreationInfo2_2{
			SPDXVersion:          SPDXVersion,
			DataLicense:          DataLicense,
			SPDXIdentifier:       SPDXIdentifier,
			DocumentName:         r.ArtifactName,
			DocumentNamespace:    getDocumentNamespace(r, cw),
			CreatorOrganizations: []string{CreatorOrganization},
			CreatorTools:         []string{CreatorTool},
			Created:              cw.clock.Now().UTC().Format(time.RFC3339Nano),
		},
		Packages: packages,
	}, nil
}

func pkgToSpdxPackage(t string, meta types.Metadata, pkg ftypes.Package) (spdx.Package2_2, error) {
	var spdxPackage spdx.Package2_2
	license := getLicense(pkg)

	pkgID, err := getPackageID(pkg)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to get %s package ID: %w", pkg.Name, err)
	}

	spdxPackage.PackageSPDXIdentifier = spdx.ElementID(pkgID)
	spdxPackage.PackageName = pkg.Name
	spdxPackage.PackageVersion = pkg.Version

	// The Declared License is what the authors of a project believe govern the package
	spdxPackage.PackageLicenseConcluded = license

	// The Concluded License field is the license the SPDX file creator believes governs the package
	spdxPackage.PackageLicenseDeclared = license

	return spdxPackage, nil
}

func getLicense(p ftypes.Package) string {
	if p.License == "" {
		return "NONE"
	}

	return p.License
}

func getDocumentNamespace(r types.Report, cw *Writer) string {
	return DocumentNamespace + "/" + string(r.ArtifactType) + "/" + r.ArtifactName + "-" + cw.newUUID().String()
}

func getPackageID(p ftypes.Package) (string, error) {
	f, err := hashstructure.Hash(p, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return "", xerrors.Errorf("could not build package ID for package=%+v: %+v", p, err)
	}

	return fmt.Sprintf("%x", f), nil
}
