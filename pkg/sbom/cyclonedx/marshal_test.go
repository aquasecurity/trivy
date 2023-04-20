package cyclonedx_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fake "k8s.io/utils/clock/testing"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
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
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2018-20623",
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
								ID:      "actionpack@7.0.0",
								Name:    "actionpack",
								Version: "7.0.0",
							},
							{
								ID:      "actioncontroller@7.0.0",
								Name:    "actioncontroller",
								Version: "7.0.0",
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
				XMLNS:        "http://cyclonedx.org/schema/bom/1.4",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_4,
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
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
							{
								Name:  "aquasecurity:trivy:Size",
								Value: "1024",
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
								Name:  "aquasecurity:trivy:DiffID",
								Value: "sha256:d871dadfb37b53ef1ca45be04fc527562b91989991a8f545345ae3be0b93f92a",
							},
							{
								Name:  "aquasecurity:trivy:RepoTag",
								Value: "rails:latest",
							},
						},
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef:  "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "binutils",
						Version: "2.30-93.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{Expression: "GPLv3+"},
						},
						PackageURL: "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
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
								Name:  "aquasecurity:trivy:SrcVersion",
								Value: "2.30",
							},
							{
								Name:  "aquasecurity:trivy:SrcRelease",
								Value: "93.el8",
							},
						},
					},
					{
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000002",
						Type:    cdx.ComponentTypeOS,
						Name:    "centos",
						Version: "8.3.2011",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "centos",
							},
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "os-pkgs",
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
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000003",
						Type:    cdx.ComponentTypeApplication,
						Name:    "app/subproject/Gemfile.lock",
						Version: "",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "bundler",
							},
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
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
								Name:  "aquasecurity:trivy:Type",
								Value: "bundler",
							},
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
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
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000005",
						Type:    cdx.ComponentTypeApplication,
						Name:    "app/datacollector.deps.json",
						Version: "",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "dotnet-core",
							},
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
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
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000006",
						Type:    cdx.ComponentTypeApplication,
						Name:    "usr/local/bin/tfsec",
						Version: "",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "gobinary",
							},
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
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
						Ref: "pkg:oci/rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?repository_url=index.docker.io%2Flibrary%2Frails&arch=arm64",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000002",
							"3ff14136-e09f-4df9-80ea-000000000003",
							"3ff14136-e09f-4df9-80ea-000000000004",
							"3ff14136-e09f-4df9-80ea-000000000005",
							"3ff14136-e09f-4df9-80ea-000000000006",
						},
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
				XMLNS:        "http://cyclonedx.org/schema/bom/1.4",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_4,
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
								Name:  "aquasecurity:trivy:SchemaVersion",
								Value: "2",
							},
							{
								Name:  "aquasecurity:trivy:Size",
								Value: "1024",
							},
							{
								Name:  "aquasecurity:trivy:ImageID",
								Value: "sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6",
							},
							{
								Name:  "aquasecurity:trivy:RepoTag",
								Value: "centos:latest",
							},
						},
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef:  "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&epoch=1&distro=centos-8.3.2011",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "acl",
						Version: "2.2.53-1.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{Expression: "GPLv2+"},
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
								Name:  "aquasecurity:trivy:SrcName",
								Value: "acl",
							},
							{
								Name:  "aquasecurity:trivy:SrcVersion",
								Value: "2.2.53",
							},
							{
								Name:  "aquasecurity:trivy:SrcRelease",
								Value: "1.el8",
							},
							{
								Name:  "aquasecurity:trivy:SrcEpoch",
								Value: "1",
							},
						},
					},
					{
						BOMRef:  "pkg:rpm/centos/glibc@2.28-151.el8?arch=aarch64&distro=centos-8.3.2011",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "glibc",
						Version: "2.28-151.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{Expression: "GPLv2+"},
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
								Name:  "aquasecurity:trivy:SrcVersion",
								Value: "2.28",
							},
							{
								Name:  "aquasecurity:trivy:SrcRelease",
								Value: "151.el8",
							},
						},
					},
					{
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000003",
						Type:    cdx.ComponentTypeOS,
						Name:    fos.CentOS,
						Version: "8.3.2011",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "centos",
							},
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "os-pkgs",
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
								Name:  "aquasecurity:trivy:PkgID",
								Value: "actionpack@7.0.0",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "gemspec",
							},
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "tools/project-john/specifications/actionpack.gemspec",
							},
							{
								Name:  "aquasecurity:trivy:LayerDiffID",
								Value: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
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
								Name:  "aquasecurity:trivy:PkgID",
								Value: "actionpack@7.0.1",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "gemspec",
							},
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "tools/project-doe/specifications/actionpack.gemspec",
							},
							{
								Name:  "aquasecurity:trivy:LayerDiffID",
								Value: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
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
						Ref: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&epoch=1&distro=centos-8.3.2011",
						Dependencies: &[]string{
							"pkg:rpm/centos/glibc@2.28-151.el8?arch=aarch64&distro=centos-8.3.2011",
						},
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
				},
			},
			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.4",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_4,
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
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000003",
						Type:   cdx.ComponentTypeApplication,
						Name:   "Gemfile.lock",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "bundler",
							},
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
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
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000003",
						Dependencies: &[]string{
							"pkg:gem/actioncable@6.1.4.1",
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
				ArtifactType:  ftypes.ArtifactRemoteRepository,
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
				XMLNS:        "http://cyclonedx.org/schema/bom/1.4",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_4,
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
							cdx.LicenseChoice{Expression: "MIT"},
						},
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "ruby-typeprof@0.20.1",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "node-pkg",
							},
							{
								Name:  "aquasecurity:trivy:FilePath",
								Value: "usr/local/lib/ruby/gems/3.1.0/gems/typeprof-0.21.1/vscode/package.json",
							},
							{
								Name:  "aquasecurity:trivy:LayerDiffID",
								Value: "sha256:661c3fd3cc16b34c070f3620ca6b03b6adac150f9a7e5d0e3c707a159990f88e",
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
				XMLNS:        "http://cyclonedx.org/schema/bom/1.4",
				BOMFormat:    "CycloneDX",
				SpecVersion:  cdx.SpecVersion1_4,
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

	clock := fake.NewFakeClock(time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var count int
			newUUID := func() uuid.UUID {
				count++
				return uuid.Must(uuid.Parse(fmt.Sprintf("3ff14136-e09f-4df9-80ea-%012d", count)))
			}

			marshaler := cyclonedx.NewMarshaler("dev", cyclonedx.WithClock(clock), cyclonedx.WithNewUUID(newUUID))
			got, err := marshaler.Marshal(tt.inputReport)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMarshaler_MarshalVulnerabilities(t *testing.T) {
	tests := []struct {
		name        string
		inputReport types.Report
		want        *cdx.BOM
	}{
		{
			name: "happy path for cyclonedx scan",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "cyclonedx.json",
				ArtifactType:  ftypes.ArtifactCycloneDX,
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
				CycloneDX: &ftypes.CycloneDX{
					SerialNumber: "urn:uuid:f08a6ccd-4dce-4759-bd84-c626675d60a7",
					Version:      1,
					Metadata: ftypes.Metadata{
						Component: ftypes.Component{
							Type: ftypes.ComponentType(cdx.ComponentTypeApplication),
							Name: "centos:8",
						},
					},
				},
				Results: types.Results{
					{
						Target: "rails:latest (centos 8.3.2011)",
						Class:  types.ClassOSPkg,
						Type:   fos.CentOS,
						Packages: []ftypes.Package{
							{
								Name:            "binutils",
								Ref:             "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
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
							},
						},
					},
					{
						Target: "rails:latest (centos 8.3.2011)",
						Class:  types.ClassOSPkg,
						Type:   fos.CentOS,
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2018-20623",
								PkgName:          "binutils",
								InstalledVersion: "2.30-93.el8",
								Ref:              "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
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
				},
			},
			want: &cdx.BOM{
				XMLNS:       "http://cyclonedx.org/schema/bom/1.4",
				BOMFormat:   "CycloneDX",
				SpecVersion: cdx.SpecVersion1_4,
				Version:     1,
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
						Name:   "centos:8",
						Type:   cdx.ComponentTypeApplication,
						BOMRef: "urn:uuid:f08a6ccd-4dce-4759-bd84-c626675d60a7/1",
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
								Ref: "urn:cdx:f08a6ccd-4dce-4759-bd84-c626675d60a7/1#pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
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
			name: "happy path for cyclonedx scan without SerialNumber",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "cyclonedx.json",
				ArtifactType:  ftypes.ArtifactCycloneDX,
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
				CycloneDX: &ftypes.CycloneDX{
					Version: 1,
					Metadata: ftypes.Metadata{
						Component: ftypes.Component{
							Type: ftypes.ComponentType(cdx.ComponentTypeApplication),
							Name: "centos:8",
						},
					},
				},
				Results: types.Results{
					{
						Target: "rails:latest (centos 8.3.2011)",
						Class:  types.ClassOSPkg,
						Type:   fos.CentOS,
						Packages: []ftypes.Package{
							{
								Name:            "binutils",
								Ref:             "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
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
							},
						},
					},
					{
						Target: "rails:latest (centos 8.3.2011)",
						Class:  types.ClassOSPkg,
						Type:   fos.CentOS,
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2018-20623",
								PkgName:          "binutils",
								InstalledVersion: "2.30-93.el8",
								Ref:              "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
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
									Title:          "binutils: Use-after-free in the error function",
									Description:    "In GNU Binutils 2.31.1, there is a use-after-free in the error function in elfcomm.c when called from the process_archive function in readelf.c via a crafted ELF file.",
									Severity:       dtypes.SeverityMedium.String(),
									VendorSeverity: dtypes.VendorSeverity{},
									CweIDs:         []string{"CWE-416"},
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
				},
			},
			want: &cdx.BOM{
				XMLNS:       "http://cyclonedx.org/schema/bom/1.4",
				BOMFormat:   "CycloneDX",
				SpecVersion: cdx.SpecVersion1_4,
				Version:     1,
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
						Name: "centos:8",
						Type: cdx.ComponentTypeApplication,
					},
				},
				Vulnerabilities: &[]cdx.Vulnerability{
					{
						ID: "CVE-2018-20623",
						Source: &cdx.Source{
							Name: string(vulnerability.RedHatOVAL),
							URL:  "https://www.redhat.com/security/data/oval/v2/",
						},
						Ratings: lo.ToPtr([]cdx.VulnerabilityRating{}),
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
	}

	clock := fake.NewFakeClock(time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var count int
			newUUID := func() uuid.UUID {
				count++
				return uuid.Must(uuid.Parse(fmt.Sprintf("3ff14136-e09f-4df9-80ea-%012d", count)))
			}

			marshaler := cyclonedx.NewMarshaler("dev", cyclonedx.WithClock(clock), cyclonedx.WithNewUUID(newUUID))
			got, err := marshaler.MarshalVulnerabilities(tt.inputReport)
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
