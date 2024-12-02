package spdx_test

import (
	"context"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdxlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	tspdx "github.com/aquasecurity/trivy/pkg/sbom/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

func annotation(t *testing.T, comment string) spdx.Annotation {
	t.Helper()

	return spdx.Annotation{
		AnnotationDate: "2021-08-25T12:20:30Z",
		AnnotationType: spdx.CategoryOther,
		Annotator: spdx.Annotator{
			Annotator:     "trivy-0.56.2",
			AnnotatorType: tspdx.PackageAnnotatorToolField,
		},
		AnnotationComment: comment,
	}
}

func TestMarshaler_Marshal(t *testing.T) {
	testCases := []struct {
		name        string
		inputReport types.Report
		wantSBOM    *spdx.Document
	}{
		{
			name: "happy path for container scan",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "rails:latest",
				ArtifactType:  artifact.TypeContainerImage,
				Metadata: types.Metadata{
					Size: 1024,
					OS: &ftypes.OS{
						Family: ftypes.CentOS,
						Name:   "8.3.2011",
						Eosl:   true,
					},
					ImageID:     "sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6",
					RepoTags:    []string{"rails:latest"},
					DiffIDs:     []string{"sha256:d871dadfb37b53ef1ca45be04fc527562b91989991a8f545345ae3be0b93f92a"},
					RepoDigests: []string{"rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177"},
					ImageConfig: v1.ConfigFile{
						Architecture: "arm64",
						Config: v1.Config{
							Labels: map[string]string{
								"vendor": "aquasecurity",
							},
						},
					},
				},
				Results: types.Results{
					{
						Target: "rails:latest (centos 8.3.2011)",
						Class:  types.ClassOSPkg,
						Type:   ftypes.CentOS,
						Packages: []ftypes.Package{
							{
								Name:    "binutils",
								Version: "2.30",
								Release: "93.el8",
								Epoch:   0,
								Arch:    "aarch64",
								Identifier: ftypes.PkgIdentifier{
									UID: "F4C10A4371C93487",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeRPM,
										Namespace: "centos",
										Name:      "binutils",
										Version:   "2.30-93.el8",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "arch",
												Value: "aarch64",
											},
											{
												Key:   "distro",
												Value: "centos-8.3.2011",
											},
										},
									},
								},
								SrcName:         "binutils",
								SrcVersion:      "2.30",
								SrcRelease:      "93.el8",
								SrcEpoch:        0,
								Modularitylabel: "",
								Licenses:        []string{"GPLv3+"},
								Maintainer:      "CentOS",
								Digest:          "md5:7459cec61bb4d1b0ca8107e25e0dd005",
							},
						},
					},
					{
						Target: "app/subproject/Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: []ftypes.Package{
							{
								Name:    "actionpack",
								Version: "7.0.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "B1A9DE534F2737AF",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "actionpack",
										Version: "7.0.1",
									},
								},
							},
							{
								Name:    "actioncontroller",
								Version: "7.0.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "1628B51BD543965D",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "actioncontroller",
										Version: "7.0.1",
									},
								},
							},
						},
					},
					{
						Target: "app/Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: []ftypes.Package{
							{
								Name:    "actionpack",
								Version: "7.0.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "92D6B6D3FF6F8FF5",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "actionpack",
										Version: "7.0.1",
									},
								},
							},
						},
					},
				},
			},
			wantSBOM: &spdx.Document{
				SPDXVersion:       spdx.Version,
				DataLicense:       spdx.DataLicense,
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "rails:latest",
				DocumentNamespace: "http://aquasecurity.github.io/trivy/container_image/rails:latest-3ff14136-e09f-4df9-80ea-000000000009",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.56.2",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier:   spdx.ElementID("Application-d8a5e692df746bd7"),
						PackageDownloadLocation: "NONE",
						PackageName:             "app/Gemfile.lock",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
						Annotations: []spdx.Annotation{
							annotation(t, "Class: lang-pkgs"),
							annotation(t, "Type: bundler"),
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Application-d8a5e692df746bd4"),
						PackageDownloadLocation: "NONE",
						PackageName:             "app/subproject/Gemfile.lock",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
						Annotations: []spdx.Annotation{
							annotation(t, "Class: lang-pkgs"),
							annotation(t, "Type: bundler"),
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("ContainerImage-d8a5e692df746bd1"),
						PackageDownloadLocation: "NONE",
						PackageName:             "rails:latest",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:oci/rails@sha256%3Aa27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?arch=arm64&repository_url=index.docker.io%2Flibrary%2Frails",
							},
						},
						Annotations: []spdx.Annotation{
							annotation(t, "DiffID: sha256:d871dadfb37b53ef1ca45be04fc527562b91989991a8f545345ae3be0b93f92a"),
							annotation(t, "ImageID: sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6"),
							annotation(t, "Labels:vendor: aquasecurity"),
							annotation(t, "RepoDigest: rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177"),
							annotation(t, "RepoTag: rails:latest"),
							annotation(t, "SchemaVersion: 2"),
							annotation(t, "Size: 1024"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeContainer,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd6"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actioncontroller",
						PackageVersion:          "7.0.1",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						Annotations: []spdx.Annotation{
							annotation(t, "PkgType: bundler"),
						},
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actioncontroller@7.0.1",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						PackageSourceInfo:     "package found in: app/subproject/Gemfile.lock",
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd5"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actionpack",
						PackageVersion:          "7.0.1",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						Annotations: []spdx.Annotation{
							annotation(t, "PkgType: bundler"),
						},
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actionpack@7.0.1",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						PackageSourceInfo:     "package found in: app/subproject/Gemfile.lock",
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd8"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actionpack",
						PackageVersion:          "7.0.1",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						Annotations: []spdx.Annotation{
							annotation(t, "PkgType: bundler"),
						},
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actionpack@7.0.1",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						PackageSourceInfo:     "package found in: app/Gemfile.lock",
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd3"),
						PackageDownloadLocation: "NONE",
						PackageName:             "binutils",
						PackageVersion:          "2.30-93.el8",
						PackageLicenseConcluded: "GPL-3.0-or-later",
						PackageLicenseDeclared:  "GPL-3.0-or-later",
						Annotations: []spdx.Annotation{
							annotation(t, "PkgType: centos"),
						},
						PackageSupplier: &spdx.Supplier{
							SupplierType: tspdx.PackageSupplierOrganization,
							Supplier:     "CentOS",
						},
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
							},
						},
						PackageSourceInfo:     "built package from: binutils 2.30-93.el8",
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageChecksums: []common.Checksum{
							{
								Algorithm: common.MD5,
								Value:     "7459cec61bb4d1b0ca8107e25e0dd005",
							},
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("OperatingSystem-d8a5e692df746bd2"),
						PackageDownloadLocation: "NONE",
						PackageName:             "centos",
						PackageVersion:          "8.3.2011",
						PrimaryPackagePurpose:   tspdx.PackagePurposeOS,
						Annotations: []spdx.Annotation{
							annotation(t, "Class: os-pkgs"),
							annotation(t, "Type: centos"),
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd4"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd5"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd4"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd6"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd7"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd8"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd4"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd7"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "OperatingSystem-d8a5e692df746bd2"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "ContainerImage-d8a5e692df746bd1"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "OperatingSystem-d8a5e692df746bd2"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd3"},
						Relationship: "CONTAINS",
					},
				},
				OtherLicenses: nil,
				Annotations:   nil,
				Reviews:       nil,
			},
		},
		{
			name: "happy path for local container scan",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "centos:latest",
				ArtifactType:  artifact.TypeContainerImage,
				Metadata: types.Metadata{
					Size: 1024,
					OS: &ftypes.OS{
						Family: ftypes.CentOS,
						Name:   "8.3.2011",
						Eosl:   true,
					},
					ImageID:     "sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6",
					RepoTags:    []string{"centos:latest"},
					RepoDigests: []string{},
					ImageConfig: v1.ConfigFile{
						Architecture: "arm64",
					},
				},
				Results: types.Results{
					{
						Target: "centos:latest (centos 8.3.2011)",
						Class:  types.ClassOSPkg,
						Type:   ftypes.CentOS,
						Packages: []ftypes.Package{
							{
								Name:    "acl",
								Version: "2.2.53",
								Release: "1.el8",
								Epoch:   1,
								Arch:    "aarch64",
								Identifier: ftypes.PkgIdentifier{
									UID: "740219943F17B1DF",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeRPM,
										Namespace: "centos",
										Name:      "acl",
										Version:   "2.2.53-1.el8",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "arch",
												Value: "aarch64",
											},
											{
												Key:   "distro",
												Value: "centos-8.3.2011",
											},
											{
												Key:   "epoch",
												Value: "1",
											},
										},
									},
								},
								SrcName:         "acl",
								SrcVersion:      "2.2.53",
								SrcRelease:      "1.el8",
								SrcEpoch:        1,
								Modularitylabel: "",
								Licenses:        []string{"GPLv2+"},
								Digest:          "md5:483792b8b5f9eb8be7dc4407733118d0",
							},
						},
					},
					{
						Target: "Ruby",
						Class:  types.ClassLangPkg,
						Type:   ftypes.GemSpec,
						Packages: []ftypes.Package{
							{
								Name:    "actionpack",
								Version: "7.0.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "E8DB2C6E35F8B990",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "actionpack",
										Version: "7.0.1",
									},
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
								},
								FilePath: "tools/project-john/specifications/actionpack.gemspec",
								Digest:   "sha1:d2f9f9aed5161f6e4116a3f9573f41cd832f137c",
							},
							{
								Name:    "actionpack",
								Version: "7.0.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "B3E70B2159CFAC50",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "actionpack",
										Version: "7.0.1",
									},
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
								},
								FilePath: "tools/project-doe/specifications/actionpack.gemspec",
								Digest:   "sha1:413f98442c83808042b5d1d2611a346b999bdca5",
							},
						},
					},
				},
			},
			wantSBOM: &spdx.Document{
				SPDXVersion:       spdx.Version,
				DataLicense:       spdx.DataLicense,
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "centos:latest",
				DocumentNamespace: "http://aquasecurity.github.io/trivy/container_image/centos:latest-3ff14136-e09f-4df9-80ea-000000000006",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.56.2",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageName:             "centos:latest",
						PackageSPDXIdentifier:   "ContainerImage-d8a5e692df746bd1",
						PackageDownloadLocation: "NONE",
						Annotations: []spdx.Annotation{
							annotation(t, "ImageID: sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6"),
							annotation(t, "RepoTag: centos:latest"),
							annotation(t, "SchemaVersion: 2"),
							annotation(t, "Size: 1024"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeContainer,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd3"),
						PackageDownloadLocation: "NONE",
						PackageName:             "acl",
						PackageVersion:          "1:2.2.53-1.el8",
						PackageLicenseConcluded: "GPL-2.0-or-later",
						PackageLicenseDeclared:  "GPL-2.0-or-later",
						Annotations: []spdx.Annotation{
							annotation(t, "PkgType: centos"),
						},
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011&epoch=1",
							},
						},
						PackageSourceInfo:     "built package from: acl 1:2.2.53-1.el8",
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						PackageChecksums: []common.Checksum{
							{
								Algorithm: common.MD5,
								Value:     "483792b8b5f9eb8be7dc4407733118d0",
							},
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd4"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actionpack",
						PackageVersion:          "7.0.1",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actionpack@7.0.1",
							},
						},
						Annotations: []spdx.Annotation{
							annotation(t, "LayerDiffID: sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488"),
							annotation(t, "PkgType: gemspec"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						FilesAnalyzed:         true,
						PackageVerificationCode: &spdx.PackageVerificationCode{
							Value: "c7526b18eaaeb410e82cb0da9288dd02b38ea171",
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd5"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actionpack",
						PackageVersion:          "7.0.1",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actionpack@7.0.1",
							},
						},
						Annotations: []spdx.Annotation{
							annotation(t, "LayerDiffID: sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488"),
							annotation(t, "PkgType: gemspec"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						FilesAnalyzed:         true,
						PackageVerificationCode: &spdx.PackageVerificationCode{
							Value: "688d98e7e5660b879fd1fc548af8c0df3b7d785a",
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("OperatingSystem-d8a5e692df746bd2"),
						PackageDownloadLocation: "NONE",
						PackageName:             "centos",
						PackageVersion:          "8.3.2011",
						PrimaryPackagePurpose:   tspdx.PackagePurposeOS,
						Annotations: []spdx.Annotation{
							annotation(t, "Class: os-pkgs"),
							annotation(t, "Type: centos"),
						},
					},
				},
				Files: []*spdx.File{
					{
						FileSPDXIdentifier: "File-fa42187221d0d0a8",
						FileName:           "tools/project-doe/specifications/actionpack.gemspec",
						Checksums: []spdx.Checksum{
							{
								Algorithm: spdx.SHA1,
								Value:     "413f98442c83808042b5d1d2611a346b999bdca5",
							},
						},
					},
					{
						FileSPDXIdentifier: "File-6a540784b0dc6d55",
						FileName:           "tools/project-john/specifications/actionpack.gemspec",
						Checksums: []spdx.Checksum{
							{
								Algorithm: spdx.SHA1,
								Value:     "d2f9f9aed5161f6e4116a3f9573f41cd832f137c",
							},
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "OperatingSystem-d8a5e692df746bd2"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd4"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd5"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "ContainerImage-d8a5e692df746bd1"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "OperatingSystem-d8a5e692df746bd2"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd3"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd4"},
						RefB:         spdx.DocElementID{ElementRefID: "File-6a540784b0dc6d55"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd5"},
						RefB:         spdx.DocElementID{ElementRefID: "File-fa42187221d0d0a8"},
						Relationship: "CONTAINS",
					},
				},

				OtherLicenses: nil,
				Annotations:   nil,
				Reviews:       nil,
			},
		},
		{
			name: "happy path for fs scan",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "masahiro331/CVE-2021-41098",
				ArtifactType:  artifact.TypeFilesystem,
				Results: types.Results{
					{
						Target: "Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: []ftypes.Package{
							{
								Name:    "actioncable",
								Version: "6.1.4.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "actioncable",
										Version: "6.1.4.1",
									},
								},
							},
						},
					},
					{
						Target: "pom.xml",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Pom,
						Packages: []ftypes.Package{
							{
								ID:      "com.example:example:1.0.0",
								Name:    "com.example:example",
								Version: "1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.example",
										Name:      "example",
										Version:   "1.0.0",
									},
								},
							},
						},
					},
				},
			},
			wantSBOM: &spdx.Document{
				SPDXVersion:       spdx.Version,
				DataLicense:       spdx.DataLicense,
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "masahiro331/CVE-2021-41098",
				DocumentNamespace: "http://aquasecurity.github.io/trivy/filesystem/masahiro331/CVE-2021-41098-3ff14136-e09f-4df9-80ea-000000000006",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.56.2",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier:   spdx.ElementID("Application-d8a5e692df746bd2"),
						PackageDownloadLocation: "NONE",
						PackageName:             "Gemfile.lock",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
						Annotations: []spdx.Annotation{
							annotation(t, "Class: lang-pkgs"),
							annotation(t, "Type: bundler"),
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Application-d8a5e692df746bd4"),
						PackageDownloadLocation: "NONE",
						PackageName:             "pom.xml",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
						Annotations: []spdx.Annotation{
							annotation(t, "Class: lang-pkgs"),
							annotation(t, "Type: pom"),
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd3"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actioncable",
						PackageVersion:          "6.1.4.1",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actioncable@6.1.4.1",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						PackageSourceInfo:     "package found in: Gemfile.lock",
						Annotations: []spdx.Annotation{
							annotation(t, "PkgType: bundler"),
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd5"),
						PackageDownloadLocation: "NONE",
						PackageName:             "com.example:example",
						PackageVersion:          "1.0.0",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:maven/com.example/example@1.0.0",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						PackageSourceInfo:     "package found in: pom.xml",
						Annotations: []spdx.Annotation{
							annotation(t, "PkgID: com.example:example:1.0.0"),
							annotation(t, "PkgType: pom"),
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Filesystem-d8a5e692df746bd1"),
						PackageDownloadLocation: "NONE",
						PackageName:             "masahiro331/CVE-2021-41098",
						Annotations: []spdx.Annotation{
							annotation(t, "SchemaVersion: 2"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd2"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd3"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd4"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd5"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Filesystem-d8a5e692df746bd1"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Filesystem-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd2"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Filesystem-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd4"},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			name: "happy path with vulnerability",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "log4j-core-2.17.0.jar",
				ArtifactType:  artifact.TypeFilesystem,
				Results: types.Results{
					{
						Target: "Java",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Jar,
						Packages: []ftypes.Package{
							{
								Name:    "org.apache.logging.log4j:log4j-core",
								Version: "2.17.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.apache.logging.log4j",
										Name:      "log4j-core",
										Version:   "2.17.0",
									},
								},
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2021-44832",
								PkgName:          "org.apache.logging.log4j:log4j-core",
								InstalledVersion: "2.17.0",
								FixedVersion:     "2.3.2, 2.12.4, 2.17.1",
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2021-44832",
							},
						},
					},
				},
			},
			wantSBOM: &spdx.Document{
				SPDXVersion:       spdx.Version,
				DataLicense:       spdx.DataLicense,
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "log4j-core-2.17.0.jar",
				DocumentNamespace: "http://aquasecurity.github.io/trivy/filesystem/log4j-core-2.17.0.jar-3ff14136-e09f-4df9-80ea-000000000003",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.56.2",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd2"),
						PackageDownloadLocation: "NONE",
						PackageName:             "org.apache.logging.log4j:log4j-core",
						PackageVersion:          "2.17.0",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
							},
							{
								Category: "SECURITY",
								RefType:  "advisory",
								Locator:  "https://avd.aquasec.com/nvd/cve-2021-44832",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						Annotations: []spdx.Annotation{
							annotation(t, "PkgType: jar"),
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Filesystem-d8a5e692df746bd1"),
						PackageDownloadLocation: "NONE",
						PackageName:             "log4j-core-2.17.0.jar",
						Annotations: []spdx.Annotation{
							annotation(t, "SchemaVersion: 2"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Filesystem-d8a5e692df746bd1"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Filesystem-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd2"},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			name: "happy path aggregate results",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "http://test-aggregate",
				ArtifactType:  artifact.TypeRepository,
				Results: types.Results{
					{
						Target: "Node.js",
						Class:  types.ClassLangPkg,
						Type:   ftypes.NodePkg,
						Packages: []ftypes.Package{
							{
								Name:    "ruby-typeprof",
								Version: "0.20.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeNPM,
										Name:    "ruby-typeprof",
										Version: "0.20.1",
									},
								},
								Licenses: []string{"MIT"},
								Layer: ftypes.Layer{
									DiffID: "sha256:661c3fd3cc16b34c070f3620ca6b03b6adac150f9a7e5d0e3c707a159990f88e",
								},
								Digest:   "sha256:a5efa82f08774597165e8c1a102d45d0406913b74c184883ac91f409ae26009d",
								FilePath: "usr/local/lib/ruby/gems/3.1.0/gems/typeprof-0.21.1/vscode/package.json",
							},
						},
					},
				},
			},
			wantSBOM: &spdx.Document{
				SPDXVersion:       spdx.Version,
				DataLicense:       spdx.DataLicense,
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "http://test-aggregate",
				DocumentNamespace: "http://aquasecurity.github.io/trivy/repository/test-aggregate-3ff14136-e09f-4df9-80ea-000000000003",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.56.2",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd2"),
						PackageDownloadLocation: "git+http://test-aggregate",
						PackageName:             "ruby-typeprof",
						PackageVersion:          "0.20.1",
						PackageLicenseConcluded: "MIT",
						PackageLicenseDeclared:  "MIT",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:npm/ruby-typeprof@0.20.1",
							},
						},
						Annotations: []spdx.Annotation{
							annotation(t, "LayerDiffID: sha256:661c3fd3cc16b34c070f3620ca6b03b6adac150f9a7e5d0e3c707a159990f88e"),
							annotation(t, "PkgType: node-pkg"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						FilesAnalyzed:         true,
						PackageVerificationCode: &spdx.PackageVerificationCode{
							Value: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
						},
					},
					{
						PackageSPDXIdentifier:   "Repository-d8a5e692df746bd1",
						PackageName:             "http://test-aggregate",
						PackageDownloadLocation: "git+http://test-aggregate",
						Annotations: []spdx.Annotation{
							annotation(t, "SchemaVersion: 2"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
				},
				Files: []*spdx.File{
					{
						FileName:           "usr/local/lib/ruby/gems/3.1.0/gems/typeprof-0.21.1/vscode/package.json",
						FileSPDXIdentifier: "File-a52825a3e5bc6dfe",
						Checksums: []common.Checksum{
							{
								Algorithm: common.SHA256,
								Value:     "a5efa82f08774597165e8c1a102d45d0406913b74c184883ac91f409ae26009d",
							},
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Repository-d8a5e692df746bd1"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd2"},
						RefB:         spdx.DocElementID{ElementRefID: "File-a52825a3e5bc6dfe"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Repository-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd2"},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			name: "happy path empty",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "empty/path",
				ArtifactType:  artifact.TypeFilesystem,
				Results:       types.Results{},
			},
			wantSBOM: &spdx.Document{
				SPDXVersion:       spdx.Version,
				DataLicense:       spdx.DataLicense,
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "empty/path",
				DocumentNamespace: "http://aquasecurity.github.io/trivy/filesystem/empty/path-3ff14136-e09f-4df9-80ea-000000000002",

				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.56.2",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageName:             "empty/path",
						PackageSPDXIdentifier:   "Filesystem-d8a5e692df746bd1",
						PackageDownloadLocation: "NONE",
						Annotations: []spdx.Annotation{
							annotation(t, "SchemaVersion: 2"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Filesystem-d8a5e692df746bd1"},
						Relationship: "DESCRIBES",
					},
				},
			},
		},
		{
			name: "happy path secret",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "secret",
				ArtifactType:  artifact.TypeFilesystem,
				Results: types.Results{
					{
						Target: "key.pem",
						Class:  types.ClassSecret,
						Secrets: []types.DetectedSecret{
							{
								RuleID:    "private-key",
								Category:  "AsymmetricPrivateKey",
								Severity:  "HIGH",
								Title:     "Asymmetric Private Key",
								StartLine: 1,
								EndLine:   1,
							},
						},
					},
				},
			},
			wantSBOM: &spdx.Document{
				SPDXVersion:       spdx.Version,
				DataLicense:       spdx.DataLicense,
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "secret",
				DocumentNamespace: "http://aquasecurity.github.io/trivy/filesystem/secret-3ff14136-e09f-4df9-80ea-000000000002",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.56.2",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageName:             "secret",
						PackageSPDXIdentifier:   "Filesystem-d8a5e692df746bd1",
						PackageDownloadLocation: "NONE",
						Annotations: []spdx.Annotation{
							annotation(t, "SchemaVersion: 2"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Filesystem-d8a5e692df746bd1"},
						Relationship: "DESCRIBES",
					},
				},
			},
		},
		{
			name: "go library local",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "go-artifact",
				ArtifactType:  artifact.TypeFilesystem,
				Results: types.Results{
					{
						Target: "/usr/local/bin/test",
						Class:  types.ClassLangPkg,
						Type:   ftypes.GoBinary,
						Packages: []ftypes.Package{
							{
								Name:    "./private_repos/cnrm.googlesource.com/cnrm/",
								Version: "",
							},
							{
								Name:    "golang.org/x/crypto",
								Version: "v0.0.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "161541A259EF014B",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "golang.org/x",
										Name:      "crypto",
										Version:   "v0.0.1",
									},
								},
							},
						},
					},
				},
			},
			wantSBOM: &spdx.Document{
				SPDXVersion:       spdx.Version,
				DataLicense:       spdx.DataLicense,
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "go-artifact",
				DocumentNamespace: "http://aquasecurity.github.io/trivy/filesystem/go-artifact-3ff14136-e09f-4df9-80ea-000000000005",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.56.2",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier:   spdx.ElementID("Application-d8a5e692df746bd2"),
						PackageDownloadLocation: "NONE",
						PackageName:             "/usr/local/bin/test",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
						Annotations: []spdx.Annotation{
							annotation(t, "Class: lang-pkgs"),
							annotation(t, "Type: gobinary"),
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd3"),
						PackageDownloadLocation: "NONE",
						PackageName:             "./private_repos/cnrm.googlesource.com/cnrm/",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						PrimaryPackagePurpose:   tspdx.PackagePurposeLibrary,
						PackageSupplier:         &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						PackageSourceInfo:       "package found in: /usr/local/bin/test",
						Annotations: []spdx.Annotation{
							annotation(t, "PkgType: gobinary"),
						},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8a5e692df746bd4"),
						PackageDownloadLocation: "NONE",
						PackageName:             "golang.org/x/crypto",
						PackageVersion:          "v0.0.1",
						PackageLicenseConcluded: "NOASSERTION",
						PackageLicenseDeclared:  "NOASSERTION",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:golang/golang.org/x/crypto@v0.0.1",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
						PackageSourceInfo:     "package found in: /usr/local/bin/test",
						Annotations: []spdx.Annotation{
							annotation(t, "PkgType: gobinary"),
						},
					},
					{
						PackageName:             "go-artifact",
						PackageSPDXIdentifier:   "Filesystem-d8a5e692df746bd1",
						PackageDownloadLocation: "NONE",
						Annotations: []spdx.Annotation{
							annotation(t, "SchemaVersion: 2"),
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd2"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd3"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd2"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8a5e692df746bd4"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Filesystem-d8a5e692df746bd1"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Filesystem-d8a5e692df746bd1"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-d8a5e692df746bd2"},
						Relationship: "CONTAINS",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := clock.With(context.Background(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			marshaler := tspdx.NewMarshaler("0.56.2")
			spdxDoc, err := marshaler.MarshalReport(ctx, tc.inputReport)
			require.NoError(t, err)

			assert.NoError(t, spdxlib.ValidateDocument(spdxDoc))
			assert.Equal(t, tc.wantSBOM, spdxDoc)
		})
	}
}

func Test_GetLicense(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{
			name: "happy path",
			input: []string{
				"GPLv2+",
			},
			want: "GPL-2.0-or-later",
		},
		{
			name: "happy path with multi license",
			input: []string{
				"GPLv2+",
				"GPLv3+",
			},
			want: "GPL-2.0-or-later AND GPL-3.0-or-later",
		},
		{
			name: "happy path with OR operator",
			input: []string{
				"GPLv2+",
				"LGPL 2.0 or GNU LESSER",
			},
			want: "GPL-2.0-or-later AND (LGPL-2.0-only OR LGPL-2.1-only)",
		},
		{
			name: "happy path with AND operator",
			input: []string{
				"GPLv2+",
				"LGPL 2.0 and GNU LESSER",
			},
			want: "GPL-2.0-or-later AND LGPL-2.0-only AND LGPL-2.1-only",
		},
		{
			name: "happy path with WITH operator",
			input: []string{
				"AFL 2.0",
				"AFL 3.0 with distribution exception",
			},
			want: "AFL-2.0 AND AFL-3.0 WITH distribution-exception",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tspdx.NormalizeLicense(tt.input))
		})
	}
}
