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
								Name:    "actioncable",
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
								Name:    "actioncable",
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
						BOMRef:     "pkg:gem/actioncable@7.0.0",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "actioncable",
						Version:    "7.0.0",
						PackageURL: "pkg:gem/actioncable@7.0.0",
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
								Ref: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=aarch64&distro=centos-8.3.2011",
							},
						},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000003",
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
						Ref: "3ff14136-e09f-4df9-80ea-000000000004",
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
						Family: "centos",
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
