package report_test

import (
	"testing"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockClock struct{}

func (m mockClock) Now() time.Time {
	return time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC)
}

func TestReportWriter_CycloneDX(t *testing.T) {
	testCases := []struct {
		name         string
		inputReport  types.Report
		expectedSBOM *cdx.BOM
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
						Family: "centos",
						Name:   "8.3.2011",
						Eosl:   true,
					},
					ImageID:     "sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6",
					RepoTags:    []string{"rails:latest"},
					RepoDigests: []string{"rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177"},
					ImageConfig: v1.ConfigFile{
						Architecture: "arm64",
					},
				},
				Results: types.Results{
					{
						Target: "rails:latest (centos 8.3.2011)",
						Class:  types.ClassOSPkg,
						Type:   "centos",
						Packages: []ftypes.Package{
							{
								Name:            "acl",
								Version:         "2.2.53",
								Release:         "1.el8",
								Epoch:           0,
								Arch:            "aarch64",
								SrcName:         "acl",
								SrcVersion:      "2.2.53",
								SrcRelease:      "1.el8",
								SrcEpoch:        0,
								Modularitylabel: "",
								License:         "GPLv2+",
							},
						},
					},
					{
						Target: "app/subproject/Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   "bundler",
						Packages: []ftypes.Package{
							{
								Name:            "actioncable",
								Version:         "7.0.0",
								Release:         "",
								Epoch:           0,
								Arch:            "",
								SrcName:         "",
								SrcVersion:      "",
								SrcRelease:      "",
								SrcEpoch:        0,
								Modularitylabel: "",
								License:         "",
							},
							{
								Name:            "actioncontroller",
								Version:         "7.0.0",
								Release:         "",
								Epoch:           0,
								Arch:            "",
								SrcName:         "",
								SrcVersion:      "",
								SrcRelease:      "",
								SrcEpoch:        0,
								Modularitylabel: "",
								License:         "",
							},
						},
					},
					{
						Target: "app/Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   "bundler",
						Packages: []ftypes.Package{
							{
								Name:            "actioncable",
								Version:         "7.0.0",
								Release:         "",
								Epoch:           0,
								Arch:            "",
								SrcName:         "",
								SrcVersion:      "",
								SrcRelease:      "",
								SrcEpoch:        0,
								Modularitylabel: "",
								License:         "",
							},
						},
					},
				},
			},

			expectedSBOM: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.3",
				BOMFormat:    "CycloneDX",
				SpecVersion:  "1.3",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-ed576c5a672e",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30.000000005Z",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "cyclonedx",
						},
					},
					Component: &cdx.Component{
						Type:       cdx.ComponentTypeContainer,
						BOMRef:     "pkg:oci/rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?repository_url=index.docker.io%2Flibrary%2Frails&arch=arm64",
						PackageURL: "pkg:oci/rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?repository_url=index.docker.io%2Flibrary%2Frails&arch=arm64",
						Name:       "rails:latest",
						Version:    "8.3.2011",
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
								Name:  "aquasecurity:trivy:Digest",
								Value: "rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177",
							},
							{
								Name:  "aquasecurity:trivy:Tag",
								Value: "rails:latest",
							},
						},
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef:  "3ff14136-e09f-4df9-80ea-ed576c5a672e",
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
						BOMRef:  "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011",
						Type:    cdx.ComponentTypeLibrary,
						Name:    "acl",
						Version: "2.2.53-1.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{Expression: "GPLv2+"},
						},
						PackageURL: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Release",
								Value: "1.el8",
							},
							{
								Name:  "aquasecurity:trivy:Arch",
								Value: "aarch64",
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
						},
					},
					{
						BOMRef:  "app/subproject/Gemfile.lock",
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
						BOMRef:     "pkg:gem/actioncable@7.0.0",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "actioncable",
						Version:    "7.0.0",
						PackageURL: "pkg:gem/actioncable@7.0.0",
						Properties: &[]cdx.Property{},
					},
					{
						BOMRef:     "pkg:gem/actioncontroller@7.0.0",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "actioncontroller",
						Version:    "7.0.0",
						PackageURL: "pkg:gem/actioncontroller@7.0.0",
						Properties: &[]cdx.Property{},
					},
					{
						BOMRef:  "app/Gemfile.lock",
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
						Ref: "3ff14136-e09f-4df9-80ea-ed576c5a672e",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011",
							},
						},
					},
					{
						Ref: "app/subproject/Gemfile.lock",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:gem/actioncable@7.0.0",
							},
							{
								Ref: "pkg:gem/actioncontroller@7.0.0",
							},
						},
					},
					{
						Ref: "app/Gemfile.lock",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:gem/actioncable@7.0.0",
							},
						},
					},
					{

						Ref: "pkg:oci/rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177?repository_url=index.docker.io%2Flibrary%2Frails&arch=arm64",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "3ff14136-e09f-4df9-80ea-ed576c5a672e",
							},
							{
								Ref: "app/subproject/Gemfile.lock",
							},
							{
								Ref: "app/Gemfile.lock",
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
				ArtifactName:  "github.com/masahiro331/CVE-2021-41098",
				ArtifactType:  ftypes.ArtifactFilesystem,
				Results: types.Results{
					{
						Target: "Gemfile.lock",
						Class:  types.ClassLangPkg,
						Type:   "bundler",
						Packages: []ftypes.Package{
							{
								Name:    "actioncable",
								Version: "6.1.4.1",
							},
							{
								Name:    "actionmailbox",
								Version: "6.1.4.1",
							},
							{
								Name:    "actionmailer",
								Version: "6.1.4.1",
							},
							{
								Name:    "nokogiri",
								Version: "1.12.4",
							},
						},
					},
				},
			},

			expectedSBOM: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.3",
				BOMFormat:    "CycloneDX",
				SpecVersion:  "1.3",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-ed576c5a672e",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30.000000005Z",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "cyclonedx",
						},
					},
					Component: &cdx.Component{
						Type:   cdx.ComponentTypeApplication,
						Name:   "github.com/masahiro331/CVE-2021-41098",
						BOMRef: "3ff14136-e09f-4df9-80ea-ed576c5a672e",
					},
				},
				Components: &[]cdx.Component{
					{
						BOMRef: "Gemfile.lock",
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
					{
						BOMRef:     "pkg:gem/actioncable@6.1.4.1",
						Type:       "library",
						Name:       "actioncable",
						Version:    "6.1.4.1",
						PackageURL: "pkg:gem/actioncable@6.1.4.1",
						Properties: &[]cdx.Property{},
					},
					{
						BOMRef:     "pkg:gem/actionmailbox@6.1.4.1",
						Type:       "library",
						Name:       "actionmailbox",
						Version:    "6.1.4.1",
						PackageURL: "pkg:gem/actionmailbox@6.1.4.1",
						Properties: &[]cdx.Property{},
					},
					{
						BOMRef:     "pkg:gem/actionmailer@6.1.4.1",
						Type:       "library",
						Name:       "actionmailer",
						Version:    "6.1.4.1",
						PackageURL: "pkg:gem/actionmailer@6.1.4.1",
						Properties: &[]cdx.Property{},
					},
					{
						BOMRef:     "pkg:gem/nokogiri@1.12.4",
						Type:       "library",
						Name:       "nokogiri",
						Version:    "1.12.4",
						PackageURL: "pkg:gem/nokogiri@1.12.4",
						Properties: &[]cdx.Property{},
					},
				},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "Gemfile.lock",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:gem/actioncable@6.1.4.1",
							},
							{
								Ref: "pkg:gem/actionmailbox@6.1.4.1",
							},
							{
								Ref: "pkg:gem/actionmailer@6.1.4.1",
							},
							{
								Ref: "pkg:gem/nokogiri@1.12.4",
							},
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-ed576c5a672e",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "Gemfile.lock",
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
				ArtifactName:  "https://github.com/masahiro331/CVE-2020-8165",
				ArtifactType:  ftypes.ArtifactRemoteRepository,
				Results:       types.Results{},
			},

			expectedSBOM: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.3",
				BOMFormat:    "CycloneDX",
				SpecVersion:  "1.3",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-ed576c5a672e",
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30.000000005Z",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "cyclonedx",
						},
					},
					Component: &cdx.Component{
						Type:   cdx.ComponentTypeApplication,
						Name:   "empty/path",
						BOMRef: "3ff14136-e09f-4df9-80ea-ed576c5a672e",
					},
				},
				Components: &[]cdx.Component{},
				Dependencies: &[]cdx.Dependency{
					{
						Ref:          "3ff14136-e09f-4df9-80ea-ed576c5a672e",
						Dependencies: &[]cdx.Dependency{},
					},
				},
			},
		},
	}
	report.Now = func() time.Time {
		return time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC)
	}
	report.GenUUID = mockUUIDGenerator{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bom, err := report.ConvertToBom(tc.inputReport, "cyclonedx")
			require.NoError(t, err)
			assert.Equal(t, tc.expectedSBOM, bom)
		})
	}
}

type mockUUIDGenerator struct{}

func (m mockUUIDGenerator) New() uuid.UUID {
	return uuid.Must(uuid.Parse("3ff14136-e09f-4df9-80ea-ed576c5a672e"))
}
