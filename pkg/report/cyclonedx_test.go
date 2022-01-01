package report_test

import (
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/stretchr/testify/assert"
)

type mockClock struct{}

func (m mockClock) Now() time.Time {
	return time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC)
}

func TestReportWriter_CycloneDX(t *testing.T) {
	testCases := []struct {
		name         string
		inputReport  report.Report
		expectedSBOM *cdx.BOM
	}{
		{
			name: "happy path",
			inputReport: report.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "rails:latest",
				ArtifactType:  types.ArtifactContainerImage,
				Metadata: report.Metadata{
					Size: 1024,
					OS: &types.OS{
						Family: "centos",
						Name:   "8.3.2011",
						Eosl:   true,
					},
					RepoTags:    []string{},
					RepoDigests: []string{},
				},
				Results: report.Results{
					{
						Target: "rails:latest (centos 8.3.2011)",
						Class:  report.ClassOSPkg,
						Type:   "centos",
						Packages: []types.Package{
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
						Target: "app/Gemfile.lock",
						Class:  report.ClassLangPkg,
						Type:   "bundler",
						Packages: []types.Package{
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
				XMLNS:       "http://cyclonedx.org/schema/bom/1.3",
				BOMFormat:   "CycloneDX",
				SpecVersion: "1.3",
				Version:     1,
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
						Type:    cdx.ComponentTypeContainer,
						Name:    "rails:latest",
						Version: "8.3.2011",
						Properties: &[]cdx.Property{
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
						BOMRef:  "rails:latest (centos 8.3.2011)",
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
						BOMRef:  "pkg:rpm/acl@2.2.53?release=1.el8&arch=aarch64&src_name=acl&src_version=2.2.53&src_release=1.el8",
						Type:    "library",
						Name:    "acl",
						Version: "2.2.53-1.el8",
						Licenses: &cdx.Licenses{
							cdx.LicenseChoice{Expression: "GPLv2+"},
						},
						PackageURL: "pkg:rpm/acl@2.2.53?release=1.el8&arch=aarch64&src_name=acl&src_version=2.2.53&src_release=1.el8",
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
						BOMRef:  "app/Gemfile.lock",
						Type:    "application",
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
						BOMRef:     "pkg:gem/actioncable@7.0.0",
						Type:       "library",
						Name:       "actioncable",
						Version:    "7.0.0",
						PackageURL: "pkg:gem/actioncable@7.0.0",
						Properties: &[]cdx.Property{},
					},
				},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "rails:latest (centos 8.3.2011)",
						Dependencies: &[]cdx.Dependency{
							{
								Ref: "pkg:rpm/acl@2.2.53?release=1.el8&arch=aarch64&src_name=acl&src_version=2.2.53&src_release=1.el8",
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
				},
			},
		},
	}
	report.Now = func() time.Time {
		return time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC)
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bom, err := report.ConvertToBom(tc.inputReport, "cyclonedx")
			assert.NoError(t, err, tc.name)
			assert.Equal(t, tc.expectedSBOM, bom)
		})
	}
}
