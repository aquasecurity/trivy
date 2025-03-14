package cyclonedx_test

import (
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

var (
	binutilsIdentifier = ftypes.PkgIdentifier{
		UID: "7CC457C23685235A",
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
	}

	actionpack700Identifier = ftypes.PkgIdentifier{
		UID: "DFF5FF40889105B2",
		PURL: &packageurl.PackageURL{
			Type:    packageurl.TypeGem,
			Name:    "actionpack",
			Version: "7.0.0",
		},
	}

	actionpack701Identifier = ftypes.PkgIdentifier{
		UID: "6B0A6392BAA7D584",
		PURL: &packageurl.PackageURL{
			Type:    packageurl.TypeGem,
			Name:    "actionpack",
			Version: "7.0.1",
		},
	}
)

func TestMarshaler_MarshalReport(t *testing.T) {
	testSBOM := core.NewBOM(core.Options{GenerateBOMRef: true})
	testSBOM.AddComponent(&core.Component{
		Root: true,
		Type: core.TypeApplication,
		Name: "jackson-databind-2.13.4.1.jar",
		PkgIdentifier: ftypes.PkgIdentifier{
			BOMRef: "aff65b54-6009-4c32-968d-748949ef46e8",
		},
		Properties: []core.Property{
			{
				Name:  "SchemaVersion",
				Value: "2",
			},
		},
	})

	tests := []struct {
		name        string
		inputReport types.Report
		want        *cdx.BOM
	}{
		{
			name: "happy path for container scan",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "rails:latest",
				ArtifactType:  ftypes.TypeContainerImage,
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
								ID:              "binutils@2.30-93.el8",
								Name:            "binutils",
								Version:         "2.30",
								Release:         "93.el8",
								Epoch:           0,
								Arch:            "aarch64",
								Identifier:      binutilsIdentifier,
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
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2018-20623",
								PkgID:            "binutils@2.30-93.el8",
								PkgName:          "binutils",
								InstalledVersion: "2.30-93.el8",
								Layer: ftypes.Layer{
									DiffID: "sha256:d871dadfb37b53ef1ca45be04fc527562b91989991a8f545345ae3be0b93f92a",
								},
								SeveritySource: vulnerability.RedHatOVAL,
								PrimaryURL:     "https://avd.aquasec.com/nvd/cve-2018-20623",
								DataSource: &dtypes.DataSource{
									ID:   vulnerability.RedHatOVAL,
									Name: "Red Hat OVAL v2",
									URL:  "https://www.redhat.com/security/data/oval/v2/",
								},
								PkgIdentifier: binutilsIdentifier,
								Vulnerability: dtypes.Vulnerability{
									Title:       "binutils: Use-after-free in the error function",
									Description: "In GNU Binutils 2.31.1, there is a use-after-free in the error function in elfcomm.c when called from the process_archive function in readelf.c via a crafted ELF file.",
									Severity:    dtypes.SeverityMedium.String(),
									VendorSeverity: dtypes.VendorSeverity{
										vulnerability.NVD:        dtypes.SeverityMedium,
										vulnerability.RedHatOVAL: dtypes.SeverityMedium,
									},
									CweIDs: []string{"CWE-416"},
									CVSS: dtypes.VendorCVSS{
										vulnerability.NVD: dtypes.CVSS{
											V2Vector: "AV:N/AC:M/Au:N/C:N/I:N/A:P",
											V3Vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
											V2Score:  4.3,
											V3Score:  5.5,
										},
										vulnerability.RedHatOVAL: dtypes.CVSS{
											V3Vector: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
											V3Score:  5.3,
										},
									},
									PublishedDate:    lo.ToPtr(time.Date(2018, 12, 31, 19, 29, 0, 0, time.UTC)),
									LastModifiedDate: lo.ToPtr(time.Date(2019, 10, 31, 1, 15, 0, 0, time.UTC)),
								},
							},
						},
					},
					{
						Target: "app/subproject/Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Bundler,
						Packages: []ftypes.Package{
							{
								// This package conflicts
								ID:         "actionpack@7.0.0",
								Name:       "actionpack",
								Version:    "7.0.0",
								Identifier: actionpack700Identifier,
								Indirect:   false,
							},
							{
								ID:      "actioncontroller@7.0.0",
								Name:    "actioncontroller",
								Version: "7.0.0",
								Identifier: ftypes.PkgIdentifier{
									UID: "41ED2619CA718170",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "actioncontroller",
										Version: "7.0.0",
									},
								},
								Indirect: false,
								DependsOn: []string{
									"actionpack@7.0.0",
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
								// This package conflicts
								ID:         "actionpack@7.0.0",
								Name:       "actionpack",
								Version:    "7.0.0",
								Identifier: actionpack700Identifier,
							},
						},
					},
					{
						Target: "app/datacollector.deps.json",
						Class:  types.ClassLangPkg,
						Type:   ftypes.DotNetCore,
						Packages: []ftypes.Package{
							{
								ID:      "Newtonsoft.Json@9.0.1",
								Name:    "Newtonsoft.Json",
								Version: "9.0.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "94AB97F672F97AFB",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeNuget,
										Name:    "Newtonsoft.Json",
										Version: "9.0.1",
									},
								},
							},
						},
					},
					{
						Target: "usr/local/bin/tfsec",
						Class:  types.ClassLangPkg,
						Type:   ftypes.GoBinary,
						Packages: []ftypes.Package{
							{
								Name:    "golang.org/x/crypto",
								Version: "v0.0.0-20210421170649-83a5a9bb288b",
								Identifier: ftypes.PkgIdentifier{
									UID: "B7183ED2CF7EB470",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "golang.org/x",
										Name:      "crypto",
										Version:   "v0.0.0-20210421170649-83a5a9bb288b",
									},
								},
							},
							// dependency has been replaced with local directory
							{
								Name:    "./api",
								Version: "",
							},
						},
					},
				},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000014",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{
							{
								Type:    cdx.ComponentTypeApplication,
								Name:    "trivy",
								Group:   "aquasecurity",
								Version: "dev",
							},
						},
					},
					Component: &cdx.Component{
						Type:       cdx.ComponentTypeContainer,
						BOMRef:     "pkg:oci/rails@sha256%3Aa27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?arch=arm64&repository_url=index.docker.io%2Flibrary%2Frails",
						PackageURL: "pkg:oci/rails@sha256%3Aa27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?arch=arm64&repository_url=index.docker.io%2Flibrary%2Frails",
						Name:       "rails:latest",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:DiffID",
								Value: "sha256:d871dadfb37b53ef1ca45be04fc527562b91989991a8f545345ae3be0b93f92a",
							},
							{
								Name:  "aquasecurity:trivy:ImageID",
								Value: "sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6",
							},
							{
								Name:  "aquasecurity:trivy:Labels:vendor",
								Value: "aquasecurity",
							},
							{
								Name:  "aquasecurity:trivy:RepoDigest",
								Value: "rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177",
							},
							{
								Name:  "aquasecurity:trivy:RepoTag",
								Value: "rails:latest",
							},
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
							{
								Name:  "aquasecurity:trivy:Size",
								Value: "1024",
							},
						},
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000002",
						Type:    cdx.ComponentTypeOS,
						Name:    "centos",
						Version: "8.3.2011",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "os-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "centos",
							},
						},
					},
					{
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000004",
						Type:    cdx.ComponentTypeApplication,
						Name:    "app/subproject/Gemfile.lock",
						Version: "",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "bundler",
							},
						},
					},
					{
						BOMRef:     "3ff14136-e09f-4df9-80ea-000000000005",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "actionpack",
						Version:    "7.0.0",
						PackageURL: "pkg:gem/actionpack@7.0.0",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "actionpack@7.0.0",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "bundler",
							},
						},
					},
					{
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000007",
						Type:    cdx.ComponentTypeApplication,
						Name:    "app/Gemfile.lock",
						Version: "",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "bundler",
							},
						},
					},
					{
						BOMRef:     "3ff14136-e09f-4df9-80ea-000000000008",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "actionpack",
						Version:    "7.0.0",
						PackageURL: "pkg:gem/actionpack@7.0.0",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "actionpack@7.0.0",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "bundler",
							},
						},
					},
					{
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000009",
						Type:    cdx.ComponentTypeApplication,
						Name:    "app/datacollector.deps.json",
						Version: "",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "dotnet-core",
							},
						},
					},
					{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000011",
						Type:   cdx.ComponentTypeApplication,
						Name:   "usr/local/bin/tfsec",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "gobinary",
							},
						},
					},
					{
						// Use UUID for local Go packages
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000013",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "./api",
						Version: "",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "gobinary",
							},
						},
					},
					{
						BOMRef:     "pkg:gem/actioncontroller@7.0.0",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "actioncontroller",
						Version:    "7.0.0",
						PackageURL: "pkg:gem/actioncontroller@7.0.0",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "actioncontroller@7.0.0",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "bundler",
							},
						},
					},
					{
						BOMRef:     "pkg:golang/golang.org/x/crypto@v0.0.0-20210421170649-83a5a9bb288b",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "golang.org/x/crypto",
						Version:    "v0.0.0-20210421170649-83a5a9bb288b",
						PackageURL: "pkg:golang/golang.org/x/crypto@v0.0.0-20210421170649-83a5a9bb288b",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "gobinary",
							},
						},
					},
					{
						BOMRef:     "pkg:nuget/Newtonsoft.Json@9.0.1",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "Newtonsoft.Json",
						Version:    "9.0.1",
						PackageURL: "pkg:nuget/Newtonsoft.Json@9.0.1",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "Newtonsoft.Json@9.0.1",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "dotnet-core",
							},
						},
					},
					{
						BOMRef:  "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "binutils",
						Version: "2.30-93.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{
								License: &cdx.License{
									Name: "GPLv3+",
								},
							},
						},
						PackageURL: "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
						Supplier: &cdx.OrganizationalEntity{
							Name: "CentOS",
						},
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "binutils@2.30-93.el8",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "centos",
							},
							{
								Name:  "aquasecurity:trivy:SrcName",
								Value: "binutils",
							},
							{
								Name:  "aquasecurity:trivy:SrcRelease",
								Value: "93.el8",
							},
							{
								Name:  "aquasecurity:trivy:SrcVersion",
								Value: "2.30",
							},
						},
						Hashes: &[]cdx.Hash{
							{
								Algorithm: cdx.HashAlgoMD5,
								Value:     "7459cec61bb4d1b0ca8107e25e0dd005",
							},
						},
					},
				},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]string{
							"pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000004",
						Dependencies: &[]string{
							"pkg:gem/actioncontroller@7.0.0",
						},
					},
					{
						Ref:          "3ff14136-e09f-4df9-80ea-000000000005",
						Dependencies: &[]string{},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000007",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000008",
						},
					},
					{
						Ref:          "3ff14136-e09f-4df9-80ea-000000000008",
						Dependencies: &[]string{},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000009",
						Dependencies: &[]string{
							"pkg:nuget/Newtonsoft.Json@9.0.1",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000011",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000013",
							"pkg:golang/golang.org/x/crypto@v0.0.0-20210421170649-83a5a9bb288b",
						},
					},
					{
						Ref:          "3ff14136-e09f-4df9-80ea-000000000013",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref: "pkg:gem/actioncontroller@7.0.0",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000005",
						},
					},
					{
						Ref:          "pkg:golang/golang.org/x/crypto@v0.0.0-20210421170649-83a5a9bb288b",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref:          "pkg:nuget/Newtonsoft.Json@9.0.1",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref: "pkg:oci/rails@sha256%3Aa27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?arch=arm64&repository_url=index.docker.io%2Flibrary%2Frails",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000002",
							"3ff14136-e09f-4df9-80ea-000000000004",
							"3ff14136-e09f-4df9-80ea-000000000007",
							"3ff14136-e09f-4df9-80ea-000000000009",
							"3ff14136-e09f-4df9-80ea-000000000011",
						},
					},
					{
						Ref:          "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
						Dependencies: lo.ToPtr([]string{}),
					},
				},
				Vulnerabilities: &[]cdx.Vulnerability{
					{
						ID: "CVE-2018-20623",
						Source: &cdx.Source{
							Name: string(vulnerability.RedHatOVAL),
							URL:  "https://www.redhat.com/security/data/oval/v2/",
						},
						Ratings: &[]cdx.VulnerabilityRating{
							{
								Source: &cdx.Source{
									Name: string(vulnerability.NVD),
									URL:  "",
								},
								Score:    lo.ToPtr(4.3),
								Severity: cdx.SeverityMedium,
								Method:   cdx.ScoringMethodCVSSv2,
								Vector:   "AV:N/AC:M/Au:N/C:N/I:N/A:P",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.NVD),
									URL:  "",
								},
								Score:    lo.ToPtr(5.5),
								Severity: cdx.SeverityMedium,
								Method:   cdx.ScoringMethodCVSSv3,
								Vector:   "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.RedHatOVAL),
									URL:  "",
								},
								Score:    lo.ToPtr(5.3),
								Severity: cdx.SeverityMedium,
								Method:   cdx.ScoringMethodCVSSv3,
								Vector:   "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
							},
						},
						CWEs: &[]int{
							416,
						},
						Description: "In GNU Binutils 2.31.1, there is a use-after-free in the error function in elfcomm.c when called from the process_archive function in readelf.c via a crafted ELF file.",
						Published:   "2018-12-31T19:29:00+00:00",
						Updated:     "2019-10-31T01:15:00+00:00",
						Advisories: &[]cdx.Advisory{
							{
								URL: "https://avd.aquasec.com/nvd/cve-2018-20623",
							},
						},
						Affects: &[]cdx.Affects{
							{
								Ref: "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
								Range: &[]cdx.AffectedVersions{
									{
										Version: "2.30-93.el8",
										Status:  cdx.VulnerabilityStatusAffected,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path for local container scan",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "centos:latest",
				ArtifactType:  ftypes.TypeContainerImage,
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
								ID:      "acl@2.2.53-1.el8",
								Name:    "acl",
								Version: "2.2.53",
								Release: "1.el8",
								Epoch:   1,
								Arch:    "aarch64",
								Identifier: ftypes.PkgIdentifier{
									UID: "2FF7A09FA4E6AA2E",
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
								DependsOn: []string{
									"glibc@2.28-151.el8",
								},
								Digest: "md5:483792b8b5f9eb8be7dc4407733118d0",
							},
							{
								ID:      "glibc@2.28-151.el8",
								Name:    "glibc",
								Version: "2.28",
								Release: "151.el8",
								Epoch:   0,
								Arch:    "aarch64",
								Identifier: ftypes.PkgIdentifier{
									UID: "2DCAB94016E57F8E",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeRPM,
										Namespace: "centos",
										Name:      "glibc",
										Version:   "2.28-151.el8",
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
								SrcName:         "glibc",
								SrcVersion:      "2.28",
								SrcRelease:      "151.el8",
								SrcEpoch:        0,
								Modularitylabel: "",
								Licenses:        []string{"GPLv2+"},
								Digest:          "md5:969b3c9231627022f8bf7ac70de807a1",
							},
						},
					},
					{
						Target: "Ruby",
						Class:  types.ClassLangPkg,
						Type:   ftypes.GemSpec,
						Packages: []ftypes.Package{
							{
								ID:         "actionpack@7.0.0",
								Name:       "actionpack",
								Version:    "7.0.0",
								Identifier: actionpack700Identifier,
								Layer: ftypes.Layer{
									DiffID: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
								},
								FilePath: "tools/project-john/specifications/actionpack.gemspec",
							},
							{
								ID:         "actionpack@7.0.1",
								Name:       "actionpack",
								Version:    "7.0.1",
								Identifier: actionpack701Identifier,
								Layer: ftypes.Layer{
									DiffID: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
								},
								FilePath: "tools/project-doe/specifications/actionpack.gemspec",
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2022-23633",
								PkgID:            "actionpack@7.0.0",
								PkgName:          "actionpack",
								PkgPath:          "tools/project-john/specifications/actionpack.gemspec",
								PkgIdentifier:    actionpack700Identifier,
								InstalledVersion: "7.0.0",
								FixedVersion:     "~> 5.2.6, >= 5.2.6.2, ~> 6.0.4, >= 6.0.4.6, ~> 6.1.4, >= 6.1.4.6, >= 7.0.2.2",
								SeveritySource:   vulnerability.RubySec,
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2022-23633",
								DataSource: &dtypes.DataSource{
									ID:   vulnerability.RubySec,
									Name: "Ruby Advisory Database",
									URL:  "https://github.com/rubysec/ruby-advisory-db",
								},
								Vulnerability: dtypes.Vulnerability{
									Title:       "rubygem-actionpack: information leak between requests",
									Description: "Action Pack is a framework for handling and responding to web requests. Under certain circumstances response bodies will not be closed. In the event a response is *not* notified of a `close`, `ActionDispatch::Executor` will not know to reset thread local state for the next request. This can lead to data being leaked to subsequent requests.This has been fixed in Rails 7.0.2.1, 6.1.4.5, 6.0.4.5, and 5.2.6.1. Upgrading is highly recommended, but to work around this problem a middleware described in GHSA-wh98-p28r-vrc9 can be used.",
									Severity:    dtypes.SeverityMedium.String(),
									VendorSeverity: dtypes.VendorSeverity{
										vulnerability.NVD:     dtypes.SeverityMedium,
										vulnerability.RedHat:  dtypes.SeverityLow,
										vulnerability.RubySec: dtypes.SeverityHigh,
									},
									CVSS: dtypes.VendorCVSS{
										vulnerability.NVD: dtypes.CVSS{
											V2Vector: "AV:N/AC:L/Au:N/C:C/I:P/A:C",
											V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
											V2Score:  9.7,
											V3Score:  5.9,
										},
										vulnerability.RedHat: dtypes.CVSS{
											V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
											V3Score:  5.9,
										},
									},
									References: []string{
										"  extraPrefix http://www.openwall.com/lists/oss-security/2022/02/11/5",
										"https://access.redhat.com/security/cve/CVE-2022-23633 (extra suffix)",
									},
									PublishedDate:    lo.ToPtr(time.Date(2022, 2, 11, 21, 15, 0, 0, time.UTC)),
									LastModifiedDate: lo.ToPtr(time.Date(2022, 2, 22, 21, 47, 0, 0, time.UTC)),
								},
							},
							{
								VulnerabilityID:  "CVE-2022-23633",
								PkgID:            "actionpack@7.0.1",
								PkgName:          "actionpack",
								PkgPath:          "tools/project-doe/specifications/actionpack.gemspec",
								PkgIdentifier:    actionpack701Identifier,
								InstalledVersion: "7.0.1",
								FixedVersion:     "~> 5.2.6, >= 5.2.6.2, ~> 6.0.4, >= 6.0.4.6, ~> 6.1.4, >= 6.1.4.6, >= 7.0.2.2",
								SeveritySource:   vulnerability.RubySec,
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2022-23633",
								DataSource: &dtypes.DataSource{
									ID:   vulnerability.RubySec,
									Name: "Ruby Advisory Database",
									URL:  "https://github.com/rubysec/ruby-advisory-db",
								},
								Vulnerability: dtypes.Vulnerability{
									Title:       "rubygem-actionpack: information leak between requests",
									Description: "Action Pack is a framework for handling and responding to web requests. Under certain circumstances response bodies will not be closed. In the event a response is *not* notified of a `close`, `ActionDispatch::Executor` will not know to reset thread local state for the next request. This can lead to data being leaked to subsequent requests.This has been fixed in Rails 7.0.2.1, 6.1.4.5, 6.0.4.5, and 5.2.6.1. Upgrading is highly recommended, but to work around this problem a middleware described in GHSA-wh98-p28r-vrc9 can be used.",
									Severity:    dtypes.SeverityMedium.String(),
									VendorSeverity: dtypes.VendorSeverity{
										vulnerability.NVD:     dtypes.SeverityMedium,
										vulnerability.RedHat:  dtypes.SeverityLow,
										vulnerability.RubySec: dtypes.SeverityHigh,
									},
									CVSS: dtypes.VendorCVSS{
										vulnerability.NVD: dtypes.CVSS{
											V2Vector: "AV:N/AC:L/Au:N/C:C/I:P/A:C",
											V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
											V2Score:  9.7,
											V3Score:  5.9,
										},
										vulnerability.RedHat: dtypes.CVSS{
											V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
											V3Score:  5.9,
										},
									},
									References: []string{
										"http://www.openwall.com/lists/oss-security/2022/02/11/5",
										"https://access.redhat.com/security/cve/CVE-2022-23633",
									},
									PublishedDate:    lo.ToPtr(time.Date(2022, 2, 11, 21, 15, 0, 0, time.UTC)),
									LastModifiedDate: lo.ToPtr(time.Date(2022, 2, 22, 21, 47, 0, 0, time.UTC)),
								},
							},
						},
					},
				},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000007",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{
							{
								Type:    cdx.ComponentTypeApplication,
								Name:    "trivy",
								Group:   "aquasecurity",
								Version: "dev",
							},
						},
					},
					Component: &cdx.Component{
						Type:       cdx.ComponentTypeContainer,
						BOMRef:     "3ff14136-e09f-4df9-80ea-000000000001",
						PackageURL: "",
						Name:       "centos:latest",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:ImageID",
								Value: "sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6",
							},
							{
								Name:  "aquasecurity:trivy:RepoTag",
								Value: "centos:latest",
							},
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
							{
								Name:  "aquasecurity:trivy:Size",
								Value: "1024",
							},
						},
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000002",
						Type:    cdx.ComponentTypeOS,
						Name:    string(ftypes.CentOS),
						Version: "8.3.2011",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "os-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "centos",
							},
						},
					},
					{
						BOMRef:     "pkg:gem/actionpack@7.0.0",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "actionpack",
						Version:    "7.0.0",
						PackageURL: "pkg:gem/actionpack@7.0.0",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "tools/project-john/specifications/actionpack.gemspec",
							},
							{
								Name:  "aquasecurity:trivy:LayerDiffID",
								Value: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
							},
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "actionpack@7.0.0",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "gemspec",
							},
						},
					},
					{
						BOMRef:     "pkg:gem/actionpack@7.0.1",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "actionpack",
						Version:    "7.0.1",
						PackageURL: "pkg:gem/actionpack@7.0.1",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "tools/project-doe/specifications/actionpack.gemspec",
							},
							{
								Name:  "aquasecurity:trivy:LayerDiffID",
								Value: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
							},
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "actionpack@7.0.1",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "gemspec",
							},
						},
					},
					{
						BOMRef:  "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011&epoch=1",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "acl",
						Version: "1:2.2.53-1.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{
								License: &cdx.License{
									Name: "GPLv2+",
								},
							},
						},
						PackageURL: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011&epoch=1",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "acl@2.2.53-1.el8",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "centos",
							},
							{
								Name:  "aquasecurity:trivy:SrcEpoch",
								Value: "1",
							},
							{
								Name:  "aquasecurity:trivy:SrcName",
								Value: "acl",
							},
							{
								Name:  "aquasecurity:trivy:SrcRelease",
								Value: "1.el8",
							},
							{
								Name:  "aquasecurity:trivy:SrcVersion",
								Value: "2.2.53",
							},
						},
						Hashes: &[]cdx.Hash{
							{
								Algorithm: cdx.HashAlgoMD5,
								Value:     "483792b8b5f9eb8be7dc4407733118d0",
							},
						},
					},
					{
						BOMRef:  "pkg:rpm/centos/glibc@2.28-151.el8?arch=aarch64&distro=centos-8.3.2011",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "glibc",
						Version: "2.28-151.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{
								License: &cdx.License{
									Name: "GPLv2+",
								},
							},
						},
						PackageURL: "pkg:rpm/centos/glibc@2.28-151.el8?arch=aarch64&distro=centos-8.3.2011",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "glibc@2.28-151.el8",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "centos",
							},
							{
								Name:  "aquasecurity:trivy:SrcName",
								Value: "glibc",
							},
							{
								Name:  "aquasecurity:trivy:SrcRelease",
								Value: "151.el8",
							},
							{
								Name:  "aquasecurity:trivy:SrcVersion",
								Value: "2.28",
							},
						},
						Hashes: &[]cdx.Hash{
							{
								Algorithm: cdx.HashAlgoMD5,
								Value:     "969b3c9231627022f8bf7ac70de807a1",
							},
						},
					},
				},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000001",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000002",
							"pkg:gem/actionpack@7.0.0",
							"pkg:gem/actionpack@7.0.1",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]string{
							"pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011&epoch=1",
						},
					},
					{
						Ref:          "pkg:gem/actionpack@7.0.0",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref:          "pkg:gem/actionpack@7.0.1",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011&epoch=1",
						Dependencies: &[]string{
							"pkg:rpm/centos/glibc@2.28-151.el8?arch=aarch64&distro=centos-8.3.2011",
						},
					},
					{
						Ref:          "pkg:rpm/centos/glibc@2.28-151.el8?arch=aarch64&distro=centos-8.3.2011",
						Dependencies: lo.ToPtr([]string{}),
					},
				},
				Vulnerabilities: &[]cdx.Vulnerability{
					{
						ID: "CVE-2022-23633",
						Source: &cdx.Source{
							Name: string(vulnerability.RubySec),
							URL:  "https://github.com/rubysec/ruby-advisory-db",
						},
						Recommendation: "Upgrade actionpack to version ~> 5.2.6, >= 5.2.6.2, ~> 6.0.4, >= 6.0.4.6, ~> 6.1.4, >= 6.1.4.6, >= 7.0.2.2",
						Ratings: &[]cdx.VulnerabilityRating{
							{
								Source: &cdx.Source{
									Name: string(vulnerability.NVD),
								},
								Score:    lo.ToPtr(9.7),
								Severity: cdx.SeverityHigh,
								Method:   cdx.ScoringMethodCVSSv2,
								Vector:   "AV:N/AC:L/Au:N/C:C/I:P/A:C",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.NVD),
								},
								Score:    lo.ToPtr(5.9),
								Severity: cdx.SeverityMedium,
								Method:   cdx.ScoringMethodCVSSv31,
								Vector:   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.RedHat),
								},
								Score:    lo.ToPtr(5.9),
								Severity: cdx.SeverityLow,
								Method:   cdx.ScoringMethodCVSSv31,
								Vector:   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.RubySec),
								},
								Severity: cdx.SeverityHigh,
							},
						},
						Description: "Action Pack is a framework for handling and responding to web requests. Under certain circumstances response bodies will not be closed. In the event a response is *not* notified of a `close`, `ActionDispatch::Executor` will not know to reset thread local state for the next request. This can lead to data being leaked to subsequent requests.This has been fixed in Rails 7.0.2.1, 6.1.4.5, 6.0.4.5, and 5.2.6.1. Upgrading is highly recommended, but to work around this problem a middleware described in GHSA-wh98-p28r-vrc9 can be used.",
						Advisories: &[]cdx.Advisory{
							{
								URL: "https://avd.aquasec.com/nvd/cve-2022-23633",
							},
							{
								URL: "http://www.openwall.com/lists/oss-security/2022/02/11/5",
							},
							{
								URL: "https://access.redhat.com/security/cve/CVE-2022-23633",
							},
						},
						Published: "2022-02-11T21:15:00+00:00",
						Updated:   "2022-02-22T21:47:00+00:00",
						Affects: &[]cdx.Affects{
							{
								Ref: "pkg:gem/actionpack@7.0.0",
								Range: &[]cdx.AffectedVersions{
									{
										Version: "7.0.0",
										Status:  cdx.VulnerabilityStatusAffected,
									},
								},
							},
							{
								Ref: "pkg:gem/actionpack@7.0.1",
								Range: &[]cdx.AffectedVersions{
									{
										Version: "7.0.1",
										Status:  cdx.VulnerabilityStatusAffected,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path for fs scan",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "masahiro331/CVE-2021-41098",
				ArtifactType:  ftypes.TypeFilesystem,
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
									UID: "2E6CF0E3CD6949BD",
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
						Target: "Java",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Jar,
						Packages: []ftypes.Package{
							{
								Name:    "org.springframework:spring-web",
								Version: "5.3.22",
								Identifier: ftypes.PkgIdentifier{
									UID: "38DDCC9B589D3124",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.springframework",
										Name:      "spring-web",
										Version:   "5.3.22",
									},
								},
								FilePath: "spring-web-5.3.22.jar",
							},
						},
					},
					{
						Target: "yarn.lock",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Yarn,
						Packages: []ftypes.Package{
							{
								ID:      "@babel/helper-string-parser@7.23.4",
								Name:    "@babel/helper-string-parser",
								Version: "7.23.4",
								Identifier: ftypes.PkgIdentifier{
									UID: "F4C833D7F3FD9ECF",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "@babel",
										Name:      "helper-string-parser",
										Version:   "7.23.4",
									},
								},
							},
						},
					},
				},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000007",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{
							{
								Type:    cdx.ComponentTypeApplication,
								Name:    "trivy",
								Group:   "aquasecurity",
								Version: "dev",
							},
						},
					},
					Component: &cdx.Component{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000001",
						Type:   cdx.ComponentTypeApplication,
						Name:   "masahiro331/CVE-2021-41098",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
						},
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000002",
						Type:   cdx.ComponentTypeApplication,
						Name:   "Gemfile.lock",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "bundler",
							},
						},
					},
					{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000005",
						Type:   cdx.ComponentTypeApplication,
						Name:   "yarn.lock",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "yarn",
							},
						},
					},
					{
						BOMRef:     "pkg:gem/actioncable@6.1.4.1",
						Type:       "library",
						Name:       "actioncable",
						Version:    "6.1.4.1",
						PackageURL: "pkg:gem/actioncable@6.1.4.1",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "bundler",
							},
						},
					},
					{
						BOMRef:     "pkg:maven/org.springframework/spring-web@5.3.22",
						Type:       "library",
						Name:       "spring-web",
						Group:      "org.springframework",
						Version:    "5.3.22",
						PackageURL: "pkg:maven/org.springframework/spring-web@5.3.22",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "spring-web-5.3.22.jar",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "jar",
							},
						},
					},
					{
						BOMRef:     "pkg:npm/%40babel/helper-string-parser@7.23.4",
						Type:       "library",
						Name:       "helper-string-parser",
						Group:      "@babel",
						Version:    "7.23.4",
						PackageURL: "pkg:npm/%40babel/helper-string-parser@7.23.4",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "@babel/helper-string-parser@7.23.4",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "yarn",
							},
						},
					},
				},
				Vulnerabilities: &[]cdx.Vulnerability{},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000001",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000002",
							"3ff14136-e09f-4df9-80ea-000000000005",
							"pkg:maven/org.springframework/spring-web@5.3.22",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]string{
							"pkg:gem/actioncable@6.1.4.1",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000005",
						Dependencies: &[]string{
							"pkg:npm/%40babel/helper-string-parser@7.23.4",
						},
					},
					{
						Ref:          "pkg:gem/actioncable@6.1.4.1",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref:          "pkg:maven/org.springframework/spring-web@5.3.22",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref:          "pkg:npm/%40babel/helper-string-parser@7.23.4",
						Dependencies: lo.ToPtr([]string{}),
					},
				},
			},
		},
		{
			name: "happy path for sbom (cyclonedx) scan",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "./report.cdx.json",
				ArtifactType:  ftypes.TypeCycloneDX,
				Results: types.Results{
					{
						Target: "Java",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Jar,
						Packages: []ftypes.Package{
							{
								Name:    "com.fasterxml.jackson.core:jackson-databind",
								Version: "2.13.4.1",
								Identifier: ftypes.PkgIdentifier{
									BOMRef: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.1",
									UID:    "9A5066570222D04C",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.fasterxml.jackson.core",
										Name:      "jackson-databind",
										Version:   "2.13.4.1",
									},
								},
								FilePath: "jackson-databind-2.13.4.1.jar",
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID: "CVE-2022-42003",
								PkgName:         "com.fasterxml.jackson.core:jackson-databind",
								PkgPath:         "jackson-databind-2.13.4.1.jar",
								PkgIdentifier: ftypes.PkgIdentifier{
									BOMRef: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.1",
									UID:    "9A5066570222D04C",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.fasterxml.jackson.core",
										Name:      "jackson-databind",
										Version:   "2.13.4.1",
									},
								},
								InstalledVersion: "2.13.4.1",
								FixedVersion:     "2.12.7.1, 2.13.4.2",
								Status:           dtypes.StatusFixed,
								SeveritySource:   "ghsa",
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2022-42003",
								DataSource: &dtypes.DataSource{
									ID:   vulnerability.GHSA,
									Name: "GitHub Security Advisory Maven",
									URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
								},
								Vulnerability: dtypes.Vulnerability{
									Title:       "jackson-databind: deep wrapper array nesting wrt UNWRAP_SINGLE_VALUE_ARRAYS",
									Description: "In FasterXML jackson-databind before versions 2.13.4.1 and 2.12.17.1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.",
									Severity:    dtypes.SeverityHigh.String(),
									VendorSeverity: dtypes.VendorSeverity{
										vulnerability.GHSA: dtypes.SeverityHigh,
									},
									CVSS: dtypes.VendorCVSS{
										vulnerability.GHSA: dtypes.CVSS{
											V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
											V3Score:  7.5,
										},
									},
									References: []string{
										"https://access.redhat.com/security/cve/CVE-2022-42003",
									},
									PublishedDate:    lo.ToPtr(time.Date(2022, 10, 02, 05, 15, 0, 0, time.UTC)),
									LastModifiedDate: lo.ToPtr(time.Date(2022, 12, 20, 10, 15, 0, 0, time.UTC)),
								},
							},
						},
					},
				},
				BOM: testSBOM,
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000002",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{
							{
								Type:    cdx.ComponentTypeApplication,
								Name:    "trivy",
								Group:   "aquasecurity",
								Version: "dev",
							},
						},
					},
					Component: &cdx.Component{
						BOMRef: "aff65b54-6009-4c32-968d-748949ef46e8", // The original bom-ref is used
						Type:   cdx.ComponentTypeApplication,
						Name:   "jackson-databind-2.13.4.1.jar",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
						},
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef:     "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.1",
						Type:       cdx.ComponentTypeLibrary,
						Group:      "com.fasterxml.jackson.core",
						Name:       "jackson-databind",
						Version:    "2.13.4.1",
						PackageURL: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.1",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "jackson-databind-2.13.4.1.jar",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "jar",
							},
						},
					},
				},
				Vulnerabilities: &[]cdx.Vulnerability{
					{
						ID: "CVE-2022-42003",
						Source: &cdx.Source{
							Name: string(vulnerability.GHSA),
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
						},
						Recommendation: "Upgrade com.fasterxml.jackson.core:jackson-databind to version 2.12.7.1, 2.13.4.2",
						Ratings: &[]cdx.VulnerabilityRating{
							{
								Source: &cdx.Source{
									Name: string(vulnerability.GHSA),
								},
								Score:    lo.ToPtr(7.5),
								Severity: cdx.SeverityHigh,
								Method:   cdx.ScoringMethodCVSSv31,
								Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
							},
						},
						Description: "In FasterXML jackson-databind before versions 2.13.4.1 and 2.12.17.1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.",
						Advisories: &[]cdx.Advisory{
							{
								URL: "https://avd.aquasec.com/nvd/cve-2022-42003",
							},
							{
								URL: "https://access.redhat.com/security/cve/CVE-2022-42003",
							},
						},
						Published: "2022-10-02T05:15:00+00:00",
						Updated:   "2022-12-20T10:15:00+00:00",
						Affects: &[]cdx.Affects{
							{
								Ref: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.1",
								Range: &[]cdx.AffectedVersions{
									{
										Version: "2.13.4.1",
										Status:  cdx.VulnerabilityStatusAffected,
									},
								},
							},
						},
					},
				},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "aff65b54-6009-4c32-968d-748949ef46e8",
						Dependencies: &[]string{
							"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.1",
						},
					},
					{
						Ref:          "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.1",
						Dependencies: lo.ToPtr([]string{}),
					},
				},
			},
		},
		{
			name: "happy path. 2 packages for 1 CVE",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "CVE-2023-34468",
				ArtifactType:  ftypes.TypeFilesystem,
				Results: types.Results{
					{
						Target: "Java",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Jar,
						Packages: []ftypes.Package{
							{
								Name:    "org.apache.nifi:nifi-dbcp-base",
								Version: "1.20.0",
								Identifier: ftypes.PkgIdentifier{
									UID: "6F266C79E57ADC38",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.apache.nifi",
										Name:      "nifi-dbcp-base",
										Version:   "1.20.0",
									},
								},
								FilePath: "nifi-dbcp-base-1.20.0.jar",
							},
							{
								Name:    "org.apache.nifi:nifi-hikari-dbcp-service",
								Version: "1.20.0",
								Identifier: ftypes.PkgIdentifier{
									UID: "3EA16F0A4CAB50F9",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.apache.nifi",
										Name:      "nifi-hikari-dbcp-service",
										Version:   "1.20.0",
									},
								},
								FilePath: "nifi-hikari-dbcp-service-1.20.0.jar",
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID: "CVE-2023-34468",
								PkgName:         "org.apache.nifi:nifi-dbcp-base",
								PkgPath:         "nifi-dbcp-base-1.20.0.jar",
								PkgIdentifier: ftypes.PkgIdentifier{
									UID: "6F266C79E57ADC38",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.apache.nifi",
										Name:      "nifi-dbcp-base",
										Version:   "1.20.0",
									},
								},
								InstalledVersion: "1.20.0",
								FixedVersion:     "1.22.0",
								SeveritySource:   vulnerability.GHSA,
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2023-34468",
								DataSource: &dtypes.DataSource{
									ID:   vulnerability.GHSA,
									Name: "GitHub Security Advisory Maven",
									URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
								},
								Vulnerability: dtypes.Vulnerability{
									Title:       "Apache NiFi vulnerable to Code Injection",
									Description: "The DBCPConnectionPool and HikariCPConnectionPool Controller Services in Apache NiFi 0.0.2 through 1.21.0...",
									Severity:    dtypes.SeverityHigh.String(),
									CweIDs: []string{
										"CWE-94",
									},
									VendorSeverity: dtypes.VendorSeverity{
										vulnerability.GHSA: dtypes.SeverityHigh,
										vulnerability.NVD:  dtypes.SeverityHigh,
									},
									CVSS: dtypes.VendorCVSS{
										vulnerability.GHSA: dtypes.CVSS{
											V3Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
											V3Score:  8.8,
										},
										vulnerability.NVD: dtypes.CVSS{
											V3Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
											V3Score:  8.8,
										},
									},
									References: []string{
										"http://www.openwall.com/lists/oss-security/2023/06/12/3",
										"https://github.com/advisories/GHSA-xm2m-2q6h-22jw",
									},
									PublishedDate:    lo.ToPtr(time.Date(2023, 6, 12, 16, 15, 0, 0, time.UTC)),
									LastModifiedDate: lo.ToPtr(time.Date(2023, 6, 21, 02, 20, 0, 0, time.UTC)),
								},
							},
							{
								VulnerabilityID: "CVE-2023-34468",
								PkgName:         "org.apache.nifi:nifi-hikari-dbcp-service",
								PkgPath:         "nifi-hikari-dbcp-service-1.20.0.jar",
								PkgIdentifier: ftypes.PkgIdentifier{
									UID: "3EA16F0A4CAB50F9",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.apache.nifi",
										Name:      "nifi-hikari-dbcp-service",
										Version:   "1.20.0",
									},
								},
								InstalledVersion: "1.20.0",
								FixedVersion:     "1.22.0",
								SeveritySource:   vulnerability.GHSA,
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2023-34468",
								DataSource: &dtypes.DataSource{
									ID:   vulnerability.GHSA,
									Name: "GitHub Security Advisory Maven",
									URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
								},
								Vulnerability: dtypes.Vulnerability{
									Title:       "Apache NiFi vulnerable to Code Injection",
									Description: "The DBCPConnectionPool and HikariCPConnectionPool Controller Services in Apache NiFi 0.0.2 through 1.21.0...",
									Severity:    dtypes.SeverityHigh.String(),
									CweIDs: []string{
										"CWE-94",
									},
									VendorSeverity: dtypes.VendorSeverity{
										vulnerability.GHSA: dtypes.SeverityHigh,
										vulnerability.NVD:  dtypes.SeverityHigh,
									},
									CVSS: dtypes.VendorCVSS{
										vulnerability.GHSA: dtypes.CVSS{
											V3Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
											V3Score:  8.8,
										},
										vulnerability.NVD: dtypes.CVSS{
											V3Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
											V3Score:  8.8,
										},
									},
									References: []string{
										"http://www.openwall.com/lists/oss-security/2023/06/12/3",
										"https://github.com/advisories/GHSA-xm2m-2q6h-22jw",
									},
									PublishedDate:    lo.ToPtr(time.Date(2023, 6, 12, 16, 15, 0, 0, time.UTC)),
									LastModifiedDate: lo.ToPtr(time.Date(2023, 6, 21, 02, 20, 0, 0, time.UTC)),
								},
							},
						},
					},
				},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000004",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{
							{
								Type:    cdx.ComponentTypeApplication,
								Name:    "trivy",
								Group:   "aquasecurity",
								Version: "dev",
							},
						},
					},
					Component: &cdx.Component{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000001",
						Type:   cdx.ComponentTypeApplication,
						Name:   "CVE-2023-34468",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
						},
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef:     "pkg:maven/org.apache.nifi/nifi-dbcp-base@1.20.0",
						Type:       "library",
						Name:       "nifi-dbcp-base",
						Group:      "org.apache.nifi",
						Version:    "1.20.0",
						PackageURL: "pkg:maven/org.apache.nifi/nifi-dbcp-base@1.20.0",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "nifi-dbcp-base-1.20.0.jar",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "jar",
							},
						},
					},
					{
						BOMRef:     "pkg:maven/org.apache.nifi/nifi-hikari-dbcp-service@1.20.0",
						Type:       "library",
						Name:       "nifi-hikari-dbcp-service",
						Group:      "org.apache.nifi",
						Version:    "1.20.0",
						PackageURL: "pkg:maven/org.apache.nifi/nifi-hikari-dbcp-service@1.20.0",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "nifi-hikari-dbcp-service-1.20.0.jar",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "jar",
							},
						},
					},
				},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000001",
						Dependencies: &[]string{
							"pkg:maven/org.apache.nifi/nifi-dbcp-base@1.20.0",
							"pkg:maven/org.apache.nifi/nifi-hikari-dbcp-service@1.20.0",
						},
					},
					{
						Ref:          "pkg:maven/org.apache.nifi/nifi-dbcp-base@1.20.0",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref:          "pkg:maven/org.apache.nifi/nifi-hikari-dbcp-service@1.20.0",
						Dependencies: lo.ToPtr([]string{}),
					},
				},
				Vulnerabilities: &[]cdx.Vulnerability{
					{
						ID: "CVE-2023-34468",
						Source: &cdx.Source{
							Name: string(vulnerability.GHSA),
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
						},
						Recommendation: "Upgrade org.apache.nifi:nifi-dbcp-base to version 1.22.0; Upgrade org.apache.nifi:nifi-hikari-dbcp-service to version 1.22.0",
						Ratings: &[]cdx.VulnerabilityRating{
							{
								Source: &cdx.Source{
									Name: string(vulnerability.GHSA),
								},
								Score:    lo.ToPtr(8.8),
								Severity: cdx.SeverityHigh,
								Method:   cdx.ScoringMethodCVSSv31,
								Vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.NVD),
								},
								Score:    lo.ToPtr(8.8),
								Severity: cdx.SeverityHigh,
								Method:   cdx.ScoringMethodCVSSv31,
								Vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
							},
						},
						CWEs:        lo.ToPtr([]int{94}),
						Description: "The DBCPConnectionPool and HikariCPConnectionPool Controller Services in Apache NiFi 0.0.2 through 1.21.0...",
						Advisories: &[]cdx.Advisory{
							{
								URL: "https://avd.aquasec.com/nvd/cve-2023-34468",
							},
							{
								URL: "http://www.openwall.com/lists/oss-security/2023/06/12/3",
							},
							{
								URL: "https://github.com/advisories/GHSA-xm2m-2q6h-22jw",
							},
						},
						Published: "2023-06-12T16:15:00+00:00",
						Updated:   "2023-06-21T02:20:00+00:00",
						Affects: &[]cdx.Affects{
							{
								Ref: "pkg:maven/org.apache.nifi/nifi-dbcp-base@1.20.0",
								Range: &[]cdx.AffectedVersions{
									{
										Version: "1.20.0",
										Status:  cdx.VulnerabilityStatusAffected,
									},
								},
							},
							{
								Ref: "pkg:maven/org.apache.nifi/nifi-hikari-dbcp-service@1.20.0",
								Range: &[]cdx.AffectedVersions{
									{
										Version: "1.20.0",
										Status:  cdx.VulnerabilityStatusAffected,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path aggregate results",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "test-aggregate",
				ArtifactType:  ftypes.TypeRepository,
				Results: types.Results{
					{
						Target: "Node.js",
						Class:  types.ClassLangPkg,
						Type:   ftypes.NodePkg,
						Packages: []ftypes.Package{
							{
								ID:      "ruby-typeprof@0.20.1",
								Name:    "ruby-typeprof",
								Version: "0.20.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "C861FD5FC7AC663F",
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
								FilePath: "usr/local/lib/ruby/gems/3.1.0/gems/typeprof-0.21.1/vscode/package.json",
							},
						},
					},
				},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000003",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{
							{
								Type:    cdx.ComponentTypeApplication,
								Name:    "trivy",
								Group:   "aquasecurity",
								Version: "dev",
							},
						},
					},
					Component: &cdx.Component{
						Type:   cdx.ComponentTypeApplication,
						Name:   "test-aggregate",
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000001",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
						},
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef:     "pkg:npm/ruby-typeprof@0.20.1",
						Type:       "library",
						Name:       "ruby-typeprof",
						Version:    "0.20.1",
						PackageURL: "pkg:npm/ruby-typeprof@0.20.1",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{
								License: &cdx.License{
									Name: "MIT",
								},
							},
						},
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "usr/local/lib/ruby/gems/3.1.0/gems/typeprof-0.21.1/vscode/package.json",
							},
							{
								Name:  "aquasecurity:trivy:LayerDiffID",
								Value: "sha256:661c3fd3cc16b34c070f3620ca6b03b6adac150f9a7e5d0e3c707a159990f88e",
							},
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "ruby-typeprof@0.20.1",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "node-pkg",
							},
						},
					},
				},
				Vulnerabilities: &[]cdx.Vulnerability{},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000001",
						Dependencies: &[]string{
							"pkg:npm/ruby-typeprof@0.20.1",
						},
					},
					{
						Ref:          "pkg:npm/ruby-typeprof@0.20.1",
						Dependencies: lo.ToPtr([]string{}),
					},
				},
			},
		},
		{
			name: "happy path empty",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "empty/path",
				ArtifactType:  ftypes.TypeFilesystem,
				Results:       types.Results{},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_6,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000002",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{
							{
								Type:    cdx.ComponentTypeApplication,
								Name:    "trivy",
								Group:   "aquasecurity",
								Version: "dev",
							},
						},
					},
					Component: &cdx.Component{
						Type:   cdx.ComponentTypeApplication,
						Name:   "empty/path",
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000001",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
						},
					},
				},
				Components:      &[]cdx.Component{},
				Vulnerabilities: &[]cdx.Vulnerability{},
				Dependencies: &[]cdx.Dependency{
					{
						Ref:          "3ff14136-e09f-4df9-80ea-000000000001",
						Dependencies: lo.ToPtr([]string{}),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := clock.With(t.Context(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			marshaler := cyclonedx.NewMarshaler("dev")
			got, err := marshaler.MarshalReport(ctx, tt.inputReport)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
