package cyclonedx_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fake "k8s.io/utils/clock/testing"

	fos "github.com/aquasecurity/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/fanal/types"
	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/report/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestWriter_Write(t *testing.T) {
	testCases := []struct {
		name        string
		inputReport types.Report
		wantSBOM    *cdx.BOM
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
								License:         "GPLv3+",
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
									PublishedDate:    timePtr(time.Date(2018, 12, 31, 19, 29, 0, 0, time.UTC)),
									LastModifiedDate: timePtr(time.Date(2019, 10, 31, 1, 15, 0, 0, time.UTC)),
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
								Name:    "actionpack",
								Version: "7.0.0",
							},
							{
								Name:    "actioncontroller",
								Version: "7.0.0",
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
								Version: "7.0.0",
							},
						},
					},
				},
			},
			wantSBOM: &cdx.BOM{
				BOMFormat:    "CycloneDX",
				SpecVersion:  "1.4",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30.000000005Z",
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
					},
					{
						BOMRef:     "pkg:gem/actioncontroller@7.0.0",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "actioncontroller",
						Version:    "7.0.0",
						PackageURL: "pkg:gem/actioncontroller@7.0.0",
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
				},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:rpm/centos/binutils@2.30-93.el8?arch=aarch64&distro=centos-8.3.2011",
							},
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000003",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:gem/actionpack@7.0.0",
							},
							{
								Ref: "pkg:gem/actioncontroller@7.0.0",
							},
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000004",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:gem/actionpack@7.0.0",
							},
						},
					},
					{
						Ref: "pkg:oci/rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?repository_url=index.docker.io%2Flibrary%2Frails&arch=arm64",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "3ff14136-e09f-4df9-80ea-000000000002",
							},
							{
								Ref: "3ff14136-e09f-4df9-80ea-000000000003",
							},
							{
								Ref: "3ff14136-e09f-4df9-80ea-000000000004",
							},
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
								Score:    4.3,
								Severity: cdx.SeverityMedium,
								Method:   cdx.ScoringMethodCVSSv2,
								Vector:   "AV:N/AC:M/Au:N/C:N/I:N/A:P",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.NVD),
									URL:  "",
								},
								Score:    5.5,
								Severity: cdx.SeverityMedium,
								Method:   cdx.ScoringMethodCVSSv3,
								Vector:   "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.RedHatOVAL),
									URL:  "",
								},
								Score:    5.3,
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
						Published: "2018-12-31 19:29:00 +0000 UTC",
						Updated:   "2019-10-31 01:15:00 +0000 UTC",
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
								License:         "GPLv2+",
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
								Version: "7.0.0",
								Layer: ftypes.Layer{
									DiffID: "sha256:ccb64cf0b7ba2e50741d0b64cae324eb5de3b1e2f580bbf177e721b67df38488",
								},
								FilePath: "tools/project-john/specifications/actionpack.gemspec",
							},
							{
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
									PublishedDate:    timePtr(time.Date(2022, 2, 11, 21, 15, 0, 0, time.UTC)),
									LastModifiedDate: timePtr(time.Date(2022, 2, 22, 21, 47, 0, 0, time.UTC)),
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
									PublishedDate:    timePtr(time.Date(2022, 2, 11, 21, 15, 0, 0, time.UTC)),
									LastModifiedDate: timePtr(time.Date(2022, 2, 22, 21, 47, 0, 0, time.UTC)),
								},
							},
						},
					},
				},
			},
			wantSBOM: &cdx.BOM{
				BOMFormat:    "CycloneDX",
				SpecVersion:  "1.4",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30.000000005Z",
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
						BOMRef:  "pkg:rpm/centos/acl@1:2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "acl",
						Version: "1:2.2.53-1.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{Expression: "GPLv2+"},
						},
						PackageURL: "pkg:rpm/centos/acl@1:2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011",
						Properties: &[]cdx.Property{
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
						Ref: "3ff14136-e09f-4df9-80ea-000000000003",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:rpm/centos/acl@1:2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011",
							},
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "3ff14136-e09f-4df9-80ea-000000000003",
							},
							{
								Ref: "pkg:gem/actionpack@7.0.0?file_path=tools%2Fproject-john%2Fspecifications%2Factionpack.gemspec",
							},
							{
								Ref: "pkg:gem/actionpack@7.0.1?file_path=tools%2Fproject-doe%2Fspecifications%2Factionpack.gemspec",
							},
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
						Ratings: &[]cdx.VulnerabilityRating{
							{
								Source: &cdx.Source{
									Name: string(vulnerability.NVD),
								},
								Score:    9.7,
								Severity: cdx.SeverityHigh,
								Method:   cdx.ScoringMethodCVSSv2,
								Vector:   "AV:N/AC:L/Au:N/C:C/I:P/A:C",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.NVD),
								},
								Score:    5.9,
								Severity: cdx.SeverityMedium,
								Method:   cdx.ScoringMethodCVSSv31,
								Vector:   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
							},
							{
								Source: &cdx.Source{
									Name: string(vulnerability.RedHat),
								},
								Score:    5.9,
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
						Published: "2022-02-11 21:15:00 +0000 UTC",
						Updated:   "2022-02-22 21:47:00 +0000 UTC",
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
			wantSBOM: &cdx.BOM{
				BOMFormat:    "CycloneDX",
				SpecVersion:  "1.4",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30.000000005Z",
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
						Ref: "3ff14136-e09f-4df9-80ea-000000000003",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:gem/actioncable@6.1.4.1",
							},
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "3ff14136-e09f-4df9-80ea-000000000003",
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
				ArtifactType:  ftypes.ArtifactRemoteRepository,
				Results: types.Results{
					{
						Target: "Node.js",
						Class:  types.ClassLangPkg,
						Type:   ftypes.NodePkg,
						Packages: []ftypes.Package{
							{
								Name:    "ruby-typeprof",
								Version: "0.20.1",
								License: "MIT",
								Layer: ftypes.Layer{
									DiffID: "sha256:661c3fd3cc16b34c070f3620ca6b03b6adac150f9a7e5d0e3c707a159990f88e",
								},
								FilePath: "usr/local/lib/ruby/gems/3.1.0/gems/typeprof-0.21.1/vscode/package.json",
							},
						},
					},
				},
			},
			wantSBOM: &cdx.BOM{
				BOMFormat:    "CycloneDX",
				SpecVersion:  "1.4",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30.000000005Z",
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
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:npm/ruby-typeprof@0.20.1?file_path=usr%2Flocal%2Flib%2Fruby%2Fgems%2F3.1.0%2Fgems%2Ftypeprof-0.21.1%2Fvscode%2Fpackage.json",
							},
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

			wantSBOM: &cdx.BOM{
				BOMFormat:    "CycloneDX",
				SpecVersion:  "1.4",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30.000000005Z",
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
				Vulnerabilities: &[]cdx.Vulnerability{},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
	}

	clock := fake.NewFakeClock(time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var count int
			newUUID := func() uuid.UUID {
				count++
				return uuid.Must(uuid.Parse(fmt.Sprintf("3ff14136-e09f-4df9-80ea-%012d", count)))
			}

			output := bytes.NewBuffer(nil)
			writer := cyclonedx.NewWriter(output, "dev", cyclonedx.WithClock(clock), cyclonedx.WithNewUUID(newUUID))

			err := writer.Write(tc.inputReport)
			require.NoError(t, err)

			var got cdx.BOM
			err = json.NewDecoder(output).Decode(&got)
			require.NoError(t, err)

			assert.Equal(t, *tc.wantSBOM, got)
		})
	}
}
func timePtr(t time.Time) *time.Time {
	return &t
}
