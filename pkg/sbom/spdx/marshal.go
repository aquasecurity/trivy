package spdx

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/spdx/tools-golang/spdx"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
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

const (
	CategoryPackageManager = "PACKAGE-MANAGER"
	RefTypePurl            = "purl"
)

type Marshaler struct {
	format  spdx.Document2_1
	clock   clock.Clock
	newUUID newUUID
	hasher  Hash
}

type Hash func(v interface{}, format hashstructure.Format, opts *hashstructure.HashOptions) (uint64, error)

type newUUID func() uuid.UUID

type marshalOption func(*Marshaler)

func WithClock(clock clock.Clock) marshalOption {
	return func(opts *Marshaler) {
		opts.clock = clock
	}
}

func WithNewUUID(newUUID newUUID) marshalOption {
	return func(opts *Marshaler) {
		opts.newUUID = newUUID
	}
}

func WithHasher(hasher Hash) marshalOption {
	return func(opts *Marshaler) {
		opts.hasher = hasher
	}
}

func NewMarshaler(opts ...marshalOption) *Marshaler {
	e := &Marshaler{
		format:  spdx.Document2_1{},
		clock:   clock.RealClock{},
		newUUID: uuid.New,
		hasher:  hashstructure.Hash,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

func (e *Marshaler) Marshal(r types.Report) (*spdx.Document2_2, error) {
	packages := make(map[spdx.ElementID]*spdx.Package2_2)

	for _, result := range r.Results {
		for _, pkg := range result.Packages {
			spdxPackage, err := e.pkgToSpdxPackage(result.Type, r.Metadata, pkg)
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
			DocumentNamespace:    getDocumentNamespace(r, e),
			CreatorOrganizations: []string{CreatorOrganization},
			CreatorTools:         []string{CreatorTool},
			Created:              e.clock.Now().UTC().Format(time.RFC3339Nano),
		},
		Packages: packages,
	}, nil
}

func (e *Marshaler) pkgToSpdxPackage(t string, metadata types.Metadata, pkg ftypes.Package) (spdx.Package2_2, error) {
	var spdxPackage spdx.Package2_2
	license := getLicense(pkg)

	pkgID, err := getPackageID(e.hasher, pkg)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to get %s package ID: %w", pkg.Name, err)
	}

	spdxPackage.PackageSPDXIdentifier = spdx.ElementID(pkgID)
	spdxPackage.PackageName = pkg.Name
	spdxPackage.PackageVersion = pkg.Version
	packageURL, err := purl.NewPackageURL(t, metadata, pkg)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to parse purl (%s): %w", pkg.Name, err)
	}
	spdxPackage.PackageExternalReferences = packageExternalReference(packageURL.String())
	// The Declared License is what the authors of a project believe govern the package
	spdxPackage.PackageLicenseConcluded = license

	// The Concluded License field is the license the SPDX file creator believes governs the package
	spdxPackage.PackageLicenseDeclared = license

	return spdxPackage, nil
}

func packageExternalReference(packageURL string) []*spdx.PackageExternalReference2_2 {
	return []*spdx.PackageExternalReference2_2{
		{
			Category: CategoryPackageManager,
			RefType:  RefTypePurl,
			Locator:  packageURL,
		},
	}
}

func getLicense(p ftypes.Package) string {
	if len(p.Licenses) == 0 {
		return "NONE"
	}

	return strings.Join(p.Licenses, ", ")
}

func getDocumentNamespace(r types.Report, e *Marshaler) string {
	return fmt.Sprintf("%s/%s/%s-%s",
		DocumentNamespace,
		string(r.ArtifactType),
		r.ArtifactName,
		e.newUUID().String(),
	)
}

func getPackageID(h Hash, p ftypes.Package) (string, error) {
	// Not use these values for the hash
	p.Layer = ftypes.Layer{}
	p.FilePath = ""

	f, err := h(p, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return "", xerrors.Errorf("could not build package ID for package=%+v: %+v", p, err)
	}

	return fmt.Sprintf("%x", f), nil
}
