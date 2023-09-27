package spdx_test

import (
	"hash/fnv"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	tspdx "github.com/aquasecurity/trivy/pkg/sbom/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

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
				ArtifactType:  ftypes.ArtifactContainerImage,
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
					},
				},
				Results: types.Results{
					{
						Target: "rails:latest (centos 8.3.2011)",
						Class:  types.ClassOSPkg,
						Type:   ftypes.CentOS,
						Packages: []ftypes.Package{
							{
								Name:            "binutils",
								Version:         "2.30",
								Release:         "93.el8",
								Epoch:           0,
								Arch:            "aarch64",
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
							},
							{
								Name:    "actioncontroller",
								Version: "7.0.1",
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
				DocumentNamespace: "http://aquasecurity.github.io/trivy/container_image/rails:latest-3ff14136-e09f-4df9-80ea-000000000001",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.38.1",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-eb0263038c3b445b"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actioncontroller",
						PackageVersion:          "7.0.1",
						PackageLicenseConcluded: "NONE",
						PackageLicenseDeclared:  "NONE",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actioncontroller@7.0.1",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-826226d056ff30c0"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actionpack",
						PackageVersion:          "7.0.1",
						PackageLicenseConcluded: "NONE",
						PackageLicenseDeclared:  "NONE",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actionpack@7.0.1",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-fd0dc3cf913d5bc3"),
						PackageDownloadLocation: "NONE",
						PackageName:             "binutils",
						PackageVersion:          "2.30-93.el8",
						PackageLicenseConcluded: "GPL-3.0-or-later",
						PackageLicenseDeclared:  "GPL-3.0-or-later",
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
						PackageSPDXIdentifier:   spdx.ElementID("Application-73c871d73f3c8248"),
						PackageDownloadLocation: "NONE",
						PackageName:             "bundler",
						PackageSourceInfo:       "app/subproject/Gemfile.lock",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Application-c3fac92c1ac0a9fa"),
						PackageDownloadLocation: "NONE",
						PackageName:             "bundler",
						PackageSourceInfo:       "app/Gemfile.lock",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("OperatingSystem-197f9a00ebcb51f0"),
						PackageDownloadLocation: "NONE",
						PackageName:             "centos",
						PackageVersion:          "8.3.2011",
						PrimaryPackagePurpose:   tspdx.PackagePurposeOS,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("ContainerImage-9396d894cd0cb6cb"),
						PackageDownloadLocation: "NONE",
						PackageName:             "rails:latest",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:oci/rails@sha256%3Aa27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?arch=arm64&repository_url=index.docker.io%2Flibrary%2Frails",
							},
						},
						PackageAttributionTexts: []string{
							"SchemaVersion: 2",
							"ImageID: sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6",
							"Size: 1024",
							"RepoDigest: rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177",
							"DiffID: sha256:d871dadfb37b53ef1ca45be04fc527562b91989991a8f545345ae3be0b93f92a",
							"RepoTag: rails:latest",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeContainer,
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "ContainerImage-9396d894cd0cb6cb"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-9396d894cd0cb6cb"},
						RefB:         spdx.DocElementID{ElementRefID: "OperatingSystem-197f9a00ebcb51f0"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "OperatingSystem-197f9a00ebcb51f0"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-fd0dc3cf913d5bc3"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-9396d894cd0cb6cb"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-73c871d73f3c8248"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-73c871d73f3c8248"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-826226d056ff30c0"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-73c871d73f3c8248"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-eb0263038c3b445b"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-9396d894cd0cb6cb"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-c3fac92c1ac0a9fa"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-c3fac92c1ac0a9fa"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-826226d056ff30c0"},
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
				ArtifactType:  ftypes.ArtifactContainerImage,
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
								Name:            "acl",
								Version:         "2.2.53",
								Release:         "1.el8",
								Epoch:           1,
								Arch:            "aarch64",
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
								Layer: ftypes.Layer{
									DiffID: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
								},
								FilePath: "tools/project-john/specifications/actionpack.gemspec",
								Digest:   "sha1:d2f9f9aed5161f6e4116a3f9573f41cd832f137c",
							},
							{
								Name:    "actionpack",
								Version: "7.0.1",
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
				DocumentNamespace: "http://aquasecurity.github.io/trivy/container_image/centos:latest-3ff14136-e09f-4df9-80ea-000000000001",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.38.1",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d8dccb186bafaf37"),
						PackageDownloadLocation: "NONE",
						PackageName:             "acl",
						PackageVersion:          "1:2.2.53-1.el8",
						PackageLicenseConcluded: "GPL-2.0-or-later",
						PackageLicenseDeclared:  "GPL-2.0-or-later",
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
						PackageSPDXIdentifier:   spdx.ElementID("Package-13fe667a0805e6b7"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actionpack",
						PackageVersion:          "7.0.1",
						PackageLicenseConcluded: "NONE",
						PackageLicenseDeclared:  "NONE",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actionpack@7.0.1",
							},
						},
						PackageAttributionTexts: []string{
							"LayerDiffID: sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-d5443dbcbba0dbd4"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actionpack",
						PackageVersion:          "7.0.1",
						PackageLicenseConcluded: "NONE",
						PackageLicenseDeclared:  "NONE",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actionpack@7.0.1",
							},
						},
						PackageAttributionTexts: []string{
							"LayerDiffID: sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("OperatingSystem-197f9a00ebcb51f0"),
						PackageDownloadLocation: "NONE",
						PackageName:             "centos",
						PackageVersion:          "8.3.2011",
						PrimaryPackagePurpose:   tspdx.PackagePurposeOS,
					},
					{
						PackageName:             "centos:latest",
						PackageSPDXIdentifier:   "ContainerImage-413bfede37ad01fc",
						PackageDownloadLocation: "NONE",
						PackageAttributionTexts: []string{
							"SchemaVersion: 2",
							"ImageID: sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6",
							"Size: 1024",
							"RepoTag: centos:latest",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeContainer,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Application-441a648f2aeeee72"),
						PackageDownloadLocation: "NONE",
						PackageName:             "gemspec",
						PackageSourceInfo:       "Ruby",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
					},
				},
				Files: []*spdx.File{
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
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "ContainerImage-413bfede37ad01fc"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-413bfede37ad01fc"},
						RefB:         spdx.DocElementID{ElementRefID: "OperatingSystem-197f9a00ebcb51f0"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "OperatingSystem-197f9a00ebcb51f0"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d8dccb186bafaf37"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "ContainerImage-413bfede37ad01fc"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-441a648f2aeeee72"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-441a648f2aeeee72"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-d5443dbcbba0dbd4"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Package-d5443dbcbba0dbd4"},
						RefB:         spdx.DocElementID{ElementRefID: "File-6a540784b0dc6d55"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-441a648f2aeeee72"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-13fe667a0805e6b7"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Package-13fe667a0805e6b7"},
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
				ArtifactType:  ftypes.ArtifactFilesystem,
				Results: types.Results{
					{
						Target: "Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: []ftypes.Package{
							{
								Name:    "actioncable",
								Version: "6.1.4.1",
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
				DocumentNamespace: "http://aquasecurity.github.io/trivy/filesystem/masahiro331/CVE-2021-41098-3ff14136-e09f-4df9-80ea-000000000001",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.38.1",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-3da61e86d0530402"),
						PackageDownloadLocation: "NONE",
						PackageName:             "actioncable",
						PackageVersion:          "6.1.4.1",
						PackageLicenseConcluded: "NONE",
						PackageLicenseDeclared:  "NONE",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:gem/actioncable@6.1.4.1",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Application-9dd4a4ba7077cc5a"),
						PackageDownloadLocation: "NONE",
						PackageName:             "bundler",
						PackageSourceInfo:       "Gemfile.lock",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Filesystem-5af0f1f08c20909a"),
						PackageDownloadLocation: "NONE",
						PackageName:             "masahiro331/CVE-2021-41098",
						PackageAttributionTexts: []string{
							"SchemaVersion: 2",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Filesystem-5af0f1f08c20909a"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Filesystem-5af0f1f08c20909a"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-9dd4a4ba7077cc5a"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-9dd4a4ba7077cc5a"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-3da61e86d0530402"},
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
				ArtifactType:  ftypes.ArtifactRepository,
				Results: types.Results{
					{
						Target: "Node.js",
						Class:  types.ClassLangPkg,
						Type:   ftypes.NodePkg,
						Packages: []ftypes.Package{
							{
								Name:     "ruby-typeprof",
								Version:  "0.20.1",
								Licenses: []string{"MIT"},
								Layer: ftypes.Layer{
									DiffID: "sha256:661c3fd3cc16b34c070f3620ca6b03b6adac150f9a7e5d0e3c707a159990f88e",
								},
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
				DocumentNamespace: "http://aquasecurity.github.io/trivy/repository/test-aggregate-3ff14136-e09f-4df9-80ea-000000000001",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.38.1",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageName:             "http://test-aggregate",
						PackageSPDXIdentifier:   "Repository-1a78857c1a6a759e",
						PackageDownloadLocation: "git+http://test-aggregate",
						PackageAttributionTexts: []string{
							"SchemaVersion: 2",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
					{
						PackageSPDXIdentifier:   "Application-24f8a80152e2c0fc",
						PackageDownloadLocation: "git+http://test-aggregate",
						PackageName:             "node-pkg",
						PackageSourceInfo:       "Node.js",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-daedb173cfd43058"),
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
						PackageAttributionTexts: []string{
							"LayerDiffID: sha256:661c3fd3cc16b34c070f3620ca6b03b6adac150f9a7e5d0e3c707a159990f88e",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
					},
				},
				Files: []*spdx.File{
					{
						FileName:           "usr/local/lib/ruby/gems/3.1.0/gems/typeprof-0.21.1/vscode/package.json",
						FileSPDXIdentifier: "File-a52825a3e5bc6dfe",
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Repository-1a78857c1a6a759e"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Repository-1a78857c1a6a759e"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-24f8a80152e2c0fc"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-24f8a80152e2c0fc"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-daedb173cfd43058"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Package-daedb173cfd43058"},
						RefB:         spdx.DocElementID{ElementRefID: "File-a52825a3e5bc6dfe"},
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
				ArtifactType:  ftypes.ArtifactFilesystem,
				Results:       types.Results{},
			},
			wantSBOM: &spdx.Document{
				SPDXVersion:       spdx.Version,
				DataLicense:       spdx.DataLicense,
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "empty/path",
				DocumentNamespace: "http://aquasecurity.github.io/trivy/filesystem/empty/path-3ff14136-e09f-4df9-80ea-000000000001",

				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.38.1",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageName:             "empty/path",
						PackageSPDXIdentifier:   "Filesystem-70f34983067dba86",
						PackageDownloadLocation: "NONE",
						PackageAttributionTexts: []string{
							"SchemaVersion: 2",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Filesystem-70f34983067dba86"},
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
				ArtifactType:  ftypes.ArtifactFilesystem,
				Results: types.Results{
					{
						Target: "key.pem",
						Class:  types.ClassSecret,
						Secrets: []ftypes.SecretFinding{
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
				DocumentNamespace: "http://aquasecurity.github.io/trivy/filesystem/secret-3ff14136-e09f-4df9-80ea-000000000001",

				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.38.1",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageName:             "secret",
						PackageSPDXIdentifier:   "Filesystem-5c08d34162a2c5d3",
						PackageDownloadLocation: "NONE",
						PackageAttributionTexts: []string{
							"SchemaVersion: 2",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Filesystem-5c08d34162a2c5d3"},
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
				ArtifactType:  ftypes.ArtifactFilesystem,
				Results: types.Results{
					{
						Target: "artifact",
						Class:  types.ClassLangPkg,
						Type:   ftypes.GoBinary,
						Packages: []ftypes.Package{
							{
								Name:    "./private_repos/cnrm.googlesource.com/cnrm/",
								Version: "(devel)",
							},
							{
								Name:    "golang.org/x/crypto",
								Version: "v0.0.1",
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
				DocumentNamespace: "http://aquasecurity.github.io/trivy/filesystem/go-artifact-3ff14136-e09f-4df9-80ea-000000000001",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{
							Creator:     "aquasecurity",
							CreatorType: "Organization",
						},
						{
							Creator:     "trivy-0.38.1",
							CreatorType: "Tool",
						},
					},
					Created: "2021-08-25T12:20:30Z",
				},
				Packages: []*spdx.Package{
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-9164ae38c5cdf815"),
						PackageDownloadLocation: "NONE",
						PackageName:             "./private_repos/cnrm.googlesource.com/cnrm/",
						PackageVersion:          "(devel)",
						PackageLicenseConcluded: "NONE",
						PackageLicenseDeclared:  "NONE",
						PrimaryPackagePurpose:   tspdx.PackagePurposeLibrary,
						PackageSupplier:         &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
					},
					{
						PackageName:             "go-artifact",
						PackageSPDXIdentifier:   "Filesystem-e340f27468b382be",
						PackageDownloadLocation: "NONE",
						PackageAttributionTexts: []string{
							"SchemaVersion: 2",
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeSource,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Application-6666b83a5d554671"),
						PackageDownloadLocation: "NONE",
						PackageName:             "gobinary",
						PackageSourceInfo:       "artifact",
						PrimaryPackagePurpose:   tspdx.PackagePurposeApplication,
					},
					{
						PackageSPDXIdentifier:   spdx.ElementID("Package-8451f2bc8e1f45aa"),
						PackageDownloadLocation: "NONE",
						PackageName:             "golang.org/x/crypto",
						PackageVersion:          "v0.0.1",
						PackageLicenseConcluded: "NONE",
						PackageLicenseDeclared:  "NONE",
						PackageExternalReferences: []*spdx.PackageExternalReference{
							{
								Category: tspdx.CategoryPackageManager,
								RefType:  tspdx.RefTypePurl,
								Locator:  "pkg:golang/golang.org/x/crypto@v0.0.1",
							},
						},
						PrimaryPackagePurpose: tspdx.PackagePurposeLibrary,
						PackageSupplier:       &spdx.Supplier{Supplier: tspdx.PackageSupplierNoAssertion},
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         spdx.DocElementID{ElementRefID: "DOCUMENT"},
						RefB:         spdx.DocElementID{ElementRefID: "Filesystem-e340f27468b382be"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Filesystem-e340f27468b382be"},
						RefB:         spdx.DocElementID{ElementRefID: "Application-6666b83a5d554671"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-6666b83a5d554671"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-9164ae38c5cdf815"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         spdx.DocElementID{ElementRefID: "Application-6666b83a5d554671"},
						RefB:         spdx.DocElementID{ElementRefID: "Package-8451f2bc8e1f45aa"},
						Relationship: "CONTAINS",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fake function calculating the hash value
			h := fnv.New64()
			hasher := func(v interface{}, format hashstructure.Format, opts *hashstructure.HashOptions) (uint64, error) {
				h.Reset()

				var str string
				switch v.(type) {
				case ftypes.Package:
					str = v.(ftypes.Package).Name + v.(ftypes.Package).FilePath
				case string:
					str = v.(string)
				case *ftypes.OS:
					str = v.(*ftypes.OS).Name
				default:
					require.Failf(t, "unknown type", "%T", v)
				}

				if _, err := h.Write([]byte(str)); err != nil {
					return 0, err
				}

				return h.Sum64(), nil
			}

			clock.SetFakeTime(t, time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			marshaler := tspdx.NewMarshaler("0.38.1", tspdx.WithHasher(hasher))
			spdxDoc, err := marshaler.Marshal(tc.inputReport)
			require.NoError(t, err)

			assert.Equal(t, tc.wantSBOM, spdxDoc)
		})
	}
}

func Test_GetLicense(t *testing.T) {
	tests := []struct {
		name  string
		input ftypes.Package
		want  string
	}{
		{
			name: "happy path",
			input: ftypes.Package{
				Licenses: []string{
					"GPLv2+",
				},
			},
			want: "GPL-2.0-or-later",
		},
		{
			name: "happy path with multi license",
			input: ftypes.Package{
				Licenses: []string{
					"GPLv2+",
					"GPLv3+",
				},
			},
			want: "GPL-2.0-or-later AND GPL-3.0-or-later",
		},
		{
			name: "happy path with OR operator",
			input: ftypes.Package{
				Licenses: []string{
					"GPLv2+",
					"LGPL 2.0 or GNU LESSER",
				},
			},
			want: "GPL-2.0-or-later AND (LGPL-2.0-only OR LGPL-3.0-only)",
		},
		{
			name: "happy path with AND operator",
			input: ftypes.Package{
				Licenses: []string{
					"GPLv2+",
					"LGPL 2.0 and GNU LESSER",
				},
			},
			want: "GPL-2.0-or-later AND LGPL-2.0-only AND LGPL-3.0-only",
		},
		{
			name: "happy path with WITH operator",
			input: ftypes.Package{
				Licenses: []string{
					"AFL 2.0",
					"AFL 3.0 with distribution exception",
				},
			},
			want: "AFL-2.0 AND AFL-3.0 WITH distribution-exception",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tspdx.GetLicense(tt.input), "getLicense(%v)", tt.input)
		})
	}
}
