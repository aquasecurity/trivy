package cyclonedx_test

import (
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/clock"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

func TestMarshaler_Marshal(t *testing.T) {
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
				ArtifactType:  ftypes.ArtifactContainerImage,
				Metadata: types.Metadata{
					Size: 1024,
					OS: &ftypes.OS{
						Family: fos.CentOS,
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
						Type:   fos.CentOS,
						Packages: []ftypes.Package{
							{
								ID:              "binutils@2.30-93.el8",
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
									References: []string{
										"http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00072.html",
										"http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00008.html",
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
								ID:       "actionpack@7.0.0",
								Name:     "actionpack",
								Version:  "7.0.0",
								Indirect: false,
							},
							{
								ID:       "actioncontroller@7.0.0",
								Name:     "actioncontroller",
								Version:  "7.0.0",
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
								ID:      "actionpack@7.0.0",
								Name:    "actionpack",
								Version: "7.0.0",
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
							},
						},
					},
				},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.5",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_5,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.5.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "dev",
						},
					},
					Component: &cdx.Component{
						Type:       cdx.ComponentTypeContainer,
						BOMRef:     "pkg:oci/rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?repository_url=index.docker.io%2Flibrary%2Frails&arch=arm64",
						PackageURL: "pkg:oci/rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?repository_url=index.docker.io%2Flibrary%2Frails&arch=arm64",
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
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000003",
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
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000004",
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
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000005",
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
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000006",
						Type:    cdx.ComponentTypeApplication,
						Name:    "usr/local/bin/tfsec",
						Version: "",
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
						BOMRef:     "pkg:gem/actionpack@7.0.0",
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
						Ref: "3ff14136-e09f-4df9-80ea-000000000003",
						Dependencies: &[]string{
							"pkg:gem/actioncontroller@7.0.0",
							"pkg:gem/actionpack@7.0.0",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000004",
						Dependencies: &[]string{
							"pkg:gem/actionpack@7.0.0",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000005",
						Dependencies: &[]string{
							"pkg:nuget/Newtonsoft.Json@9.0.1",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000006",
						Dependencies: &[]string{
							"pkg:golang/golang.org/x/crypto@v0.0.0-20210421170649-83a5a9bb288b",
						},
					},
					{
						Ref: "pkg:gem/actioncontroller@7.0.0",
						Dependencies: &[]string{
							"pkg:gem/actionpack@7.0.0",
						},
					},
					{
						Ref:          "pkg:gem/actionpack@7.0.0",
						Dependencies: lo.ToPtr([]string{}),
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
						Ref: "pkg:oci/rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?repository_url=index.docker.io%2Flibrary%2Frails&arch=arm64",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000002",
							"3ff14136-e09f-4df9-80ea-000000000003",
							"3ff14136-e09f-4df9-80ea-000000000004",
							"3ff14136-e09f-4df9-80ea-000000000005",
							"3ff14136-e09f-4df9-80ea-000000000006",
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
						Advisories: &[]cdx.Advisory{
							{
								URL: "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00072.html",
							},
							{
								URL: "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00008.html",
							},
						},
						Published: "2018-12-31T19:29:00+00:00",
						Updated:   "2019-10-31T01:15:00+00:00",
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
				ArtifactType:  ftypes.ArtifactContainerImage,
				Metadata: types.Metadata{
					Size: 1024,
					OS: &ftypes.OS{
						Family: fos.CentOS,
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
						Type:   fos.CentOS,
						Packages: []ftypes.Package{
							{
								ID:              "acl@2.2.53-1.el8",
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
								DependsOn: []string{
									"glibc@2.28-151.el8",
								},
								Digest: "md5:483792b8b5f9eb8be7dc4407733118d0",
							},
							{
								ID:              "glibc@2.28-151.el8",
								Name:            "glibc",
								Version:         "2.28",
								Release:         "151.el8",
								Epoch:           0,
								Arch:            "aarch64",
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
								ID:      "actionpack@7.0.0",
								Name:    "actionpack",
								Version: "7.0.0",
								Layer: ftypes.Layer{
									DiffID: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
								},
								FilePath: "tools/project-john/specifications/actionpack.gemspec",
							},
							{
								ID:      "actionpack@7.0.1",
								Name:    "actionpack",
								Version: "7.0.1",
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
										"http://www.openwall.com/lists/oss-security/2022/02/11/5",
										"https://access.redhat.com/security/cve/CVE-2022-23633",
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
				XMLNS:        "http://cyclonedx.org/schema/bom/1.5",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_5,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.5.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "dev",
						},
					},
					Component: &cdx.Component{
						Type:       cdx.ComponentTypeContainer,
						BOMRef:     "3ff14136-e09f-4df9-80ea-000000000002",
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
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000003",
						Type:    cdx.ComponentTypeOS,
						Name:    fos.CentOS,
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
						BOMRef:     "pkg:gem/actionpack@7.0.0?file_path=tools%2Fproject-john%2Fspecifications%2Factionpack.gemspec",
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
						BOMRef:     "pkg:gem/actionpack@7.0.1?file_path=tools%2Fproject-doe%2Fspecifications%2Factionpack.gemspec",
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
						BOMRef:  "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&epoch=1&distro=centos-8.3.2011",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "acl",
						Version: "2.2.53-1.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{
								License: &cdx.License{
									Name: "GPLv2+",
								},
							},
						},
						PackageURL: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&epoch=1&distro=centos-8.3.2011",
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
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000003",
							"pkg:gem/actionpack@7.0.0?file_path=tools%2Fproject-john%2Fspecifications%2Factionpack.gemspec",
							"pkg:gem/actionpack@7.0.1?file_path=tools%2Fproject-doe%2Fspecifications%2Factionpack.gemspec",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000003",
						Dependencies: &[]string{
							"pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&epoch=1&distro=centos-8.3.2011",
							// Trivy is unable to identify the direct OS packages as of today.
							"pkg:rpm/centos/glibc@2.28-151.el8?arch=aarch64&distro=centos-8.3.2011",
						},
					},
					{
						Ref:          "pkg:gem/actionpack@7.0.0?file_path=tools%2Fproject-john%2Fspecifications%2Factionpack.gemspec",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref:          "pkg:gem/actionpack@7.0.1?file_path=tools%2Fproject-doe%2Fspecifications%2Factionpack.gemspec",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&epoch=1&distro=centos-8.3.2011",
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
								Ref: "pkg:gem/actionpack@7.0.0?file_path=tools%2Fproject-john%2Fspecifications%2Factionpack.gemspec",
								Range: &[]cdx.AffectedVersions{
									{
										Version: "7.0.0",
										Status:  cdx.VulnerabilityStatusAffected,
									},
								},
							},
							{
								Ref: "pkg:gem/actionpack@7.0.1?file_path=tools%2Fproject-doe%2Fspecifications%2Factionpack.gemspec",
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
					{
						Target: "Java",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Jar,
						Packages: []ftypes.Package{
							{
								Name:     "org.springframework:spring-web",
								Version:  "5.3.22",
								FilePath: "spring-web-5.3.22.jar",
							},
						},
					},
				},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.5",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_5,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.5.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "dev",
						},
					},
					Component: &cdx.Component{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000002",
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
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000003",
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
						BOMRef:     "pkg:maven/org.springframework/spring-web@5.3.22?file_path=spring-web-5.3.22.jar",
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
				},
				Vulnerabilities: &[]cdx.Vulnerability{},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000003",
							"pkg:maven/org.springframework/spring-web@5.3.22?file_path=spring-web-5.3.22.jar",
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000003",
						Dependencies: &[]string{
							"pkg:gem/actioncable@6.1.4.1",
						},
					},
					{
						Ref:          "pkg:gem/actioncable@6.1.4.1",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref:          "pkg:maven/org.springframework/spring-web@5.3.22?file_path=spring-web-5.3.22.jar",
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
				ArtifactType:  ftypes.ArtifactFilesystem,
				Results: types.Results{
					{
						Target: "Java",
						Class:  types.ClassLangPkg,
						Type:   ftypes.Jar,
						Packages: []ftypes.Package{
							{
								Name:     "org.apache.nifi:nifi-dbcp-base",
								Version:  "1.20.0",
								FilePath: "nifi-dbcp-base-1.20.0.jar",
							},
							{
								Name:     "org.apache.nifi:nifi-hikari-dbcp-service",
								Version:  "1.20.0",
								FilePath: "nifi-hikari-dbcp-service-1.20.0.jar",
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2023-34468",
								PkgName:          "org.apache.nifi:nifi-dbcp-base",
								PkgPath:          "nifi-dbcp-base-1.20.0.jar",
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
								VulnerabilityID:  "CVE-2023-34468",
								PkgName:          "org.apache.nifi:nifi-hikari-dbcp-service",
								PkgPath:          "nifi-hikari-dbcp-service-1.20.0.jar",
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
				XMLNS:        "http://cyclonedx.org/schema/bom/1.5",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_5,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.5.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "dev",
						},
					},
					Component: &cdx.Component{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000002",
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
						BOMRef:     "pkg:maven/org.apache.nifi/nifi-dbcp-base@1.20.0?file_path=nifi-dbcp-base-1.20.0.jar",
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
						BOMRef:     "pkg:maven/org.apache.nifi/nifi-hikari-dbcp-service@1.20.0?file_path=nifi-hikari-dbcp-service-1.20.0.jar",
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
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]string{
							"pkg:maven/org.apache.nifi/nifi-dbcp-base@1.20.0?file_path=nifi-dbcp-base-1.20.0.jar",
							"pkg:maven/org.apache.nifi/nifi-hikari-dbcp-service@1.20.0?file_path=nifi-hikari-dbcp-service-1.20.0.jar",
						},
					},
					{
						Ref:          "pkg:maven/org.apache.nifi/nifi-dbcp-base@1.20.0?file_path=nifi-dbcp-base-1.20.0.jar",
						Dependencies: lo.ToPtr([]string{}),
					},
					{
						Ref:          "pkg:maven/org.apache.nifi/nifi-hikari-dbcp-service@1.20.0?file_path=nifi-hikari-dbcp-service-1.20.0.jar",
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
								Ref: "pkg:maven/org.apache.nifi/nifi-dbcp-base@1.20.0?file_path=nifi-dbcp-base-1.20.0.jar",
								Range: &[]cdx.AffectedVersions{
									{
										Version: "1.20.0",
										Status:  cdx.VulnerabilityStatusAffected,
									},
								},
							},
							{
								Ref: "pkg:maven/org.apache.nifi/nifi-hikari-dbcp-service@1.20.0?file_path=nifi-hikari-dbcp-service-1.20.0.jar",
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
				ArtifactType:  ftypes.ArtifactRepository,
				Results: types.Results{
					{
						Target: "Node.js",
						Class:  types.ClassLangPkg,
						Type:   ftypes.NodePkg,
						Packages: []ftypes.Package{
							{
								ID:       "ruby-typeprof@0.20.1",
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
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.5",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_5,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.5.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "dev",
						},
					},
					Component: &cdx.Component{
						Type:   cdx.ComponentTypeApplication,
						Name:   "test-aggregate",
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000002",
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
						BOMRef:     "pkg:npm/ruby-typeprof@0.20.1?file_path=usr%2Flocal%2Flib%2Fruby%2Fgems%2F3.1.0%2Fgems%2Ftypeprof-0.21.1%2Fvscode%2Fpackage.json",
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
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]string{
							"pkg:npm/ruby-typeprof@0.20.1?file_path=usr%2Flocal%2Flib%2Fruby%2Fgems%2F3.1.0%2Fgems%2Ftypeprof-0.21.1%2Fvscode%2Fpackage.json",
						},
					},
					{
						Ref:          "pkg:npm/ruby-typeprof@0.20.1?file_path=usr%2Flocal%2Flib%2Fruby%2Fgems%2F3.1.0%2Fgems%2Ftypeprof-0.21.1%2Fvscode%2Fpackage.json",
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
				ArtifactType:  ftypes.ArtifactFilesystem,
				Results:       types.Results{},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.5",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_5,
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.5.schema.json",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "dev",
						},
					},
					Component: &cdx.Component{
						Type:   cdx.ComponentTypeApplication,
						Name:   "empty/path",
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000002",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
						},
					},
				},
				Components:      lo.ToPtr([]cdx.Component{}),
				Vulnerabilities: &[]cdx.Vulnerability{},
				Dependencies: &[]cdx.Dependency{
					{
						Ref:          "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: lo.ToPtr([]string{}),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock.SetFakeTime(t, time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			marshaler := cyclonedx.NewMarshaler("dev")
			got, err := marshaler.Marshal(tt.inputReport)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
