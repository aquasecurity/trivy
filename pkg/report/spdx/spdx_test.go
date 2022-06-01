package spdx_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	fos "github.com/aquasecurity/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	reportSpdx "github.com/aquasecurity/trivy/pkg/report/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/jsonloader"
	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fake "k8s.io/utils/clock/testing"
)

func TestWriter_Write(t *testing.T) {
	testCases := []struct {
		name        string
		inputReport types.Report
		wantSBOM    *spdx.Document2_2
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
			wantSBOM: &spdx.Document2_2{
				CreationInfo: &spdx.CreationInfo2_2{
					SPDXVersion:                "SPDX-2.2",
					DataLicense:                "CC0-1.0",
					SPDXIdentifier:             "DOCUMENT",
					DocumentName:               "rails:latest",
					DocumentNamespace:          "http://aquasecurity.github.io/trivy/container_image/rails:latest-3ff14136-e09f-4df9-80ea-000000000001",
					CreatorOrganizations:       []string{"aquasecurity"},
					CreatorTools:               []string{"trivy"},
					Created:                    "2021-08-25T12:20:30.000000005Z",
					ExternalDocumentReferences: map[string]spdx.ExternalDocumentRef2_2{},
				},
				Packages: map[spdx.ElementID]*spdx.Package2_2{
					spdx.ElementID("3639080be74a6685"): {
						PackageSPDXIdentifier:     spdx.ElementID("3639080be74a6685"),
						PackageName:               "actioncontroller",
						PackageVersion:            "7.0.0",
						PackageLicenseConcluded:   "NONE",
						PackageLicenseDeclared:    "NONE",
						IsFilesAnalyzedTagPresent: true,
					},
					spdx.ElementID("8ee950e6d31d8cf9"): {
						PackageSPDXIdentifier:     spdx.ElementID("8ee950e6d31d8cf9"),
						PackageName:               "actionpack",
						PackageVersion:            "7.0.0",
						PackageLicenseConcluded:   "NONE",
						PackageLicenseDeclared:    "NONE",
						IsFilesAnalyzedTagPresent: true,
					},
					spdx.ElementID("d234c2159623e835"): {
						PackageSPDXIdentifier:     spdx.ElementID("d234c2159623e835"),
						PackageName:               "binutils",
						PackageVersion:            "2.30",
						PackageLicenseConcluded:   "GPLv3+",
						PackageLicenseDeclared:    "GPLv3+",
						IsFilesAnalyzedTagPresent: true,
					},
				},
				UnpackagedFiles: nil,
				OtherLicenses:   nil,
				Relationships:   nil,
				Annotations:     nil,
				Reviews:         nil,
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
					},
				},
			},
			wantSBOM: &spdx.Document2_2{
				CreationInfo: &spdx.CreationInfo2_2{
					SPDXVersion:                "SPDX-2.2",
					DataLicense:                "CC0-1.0",
					SPDXIdentifier:             "DOCUMENT",
					DocumentName:               "centos:latest",
					DocumentNamespace:          "http://aquasecurity.github.io/trivy/container_image/centos:latest-3ff14136-e09f-4df9-80ea-000000000001",
					CreatorOrganizations:       []string{"aquasecurity"},
					CreatorTools:               []string{"trivy"},
					Created:                    "2021-08-25T12:20:30.000000005Z",
					ExternalDocumentReferences: map[string]spdx.ExternalDocumentRef2_2{},
				},
				Packages: map[spdx.ElementID]*spdx.Package2_2{
					spdx.ElementID("bb78dad8374b2a15"): {
						PackageSPDXIdentifier:     spdx.ElementID("bb78dad8374b2a15"),
						PackageName:               "acl",
						PackageVersion:            "2.2.53",
						PackageLicenseConcluded:   "GPLv2+",
						PackageLicenseDeclared:    "GPLv2+",
						IsFilesAnalyzedTagPresent: true,
					},
					spdx.ElementID("73217041edb86985"): {
						PackageSPDXIdentifier:     spdx.ElementID("73217041edb86985"),
						PackageName:               "actionpack",
						PackageVersion:            "7.0.0",
						PackageLicenseConcluded:   "NONE",
						PackageLicenseDeclared:    "NONE",
						IsFilesAnalyzedTagPresent: true,
					},
					spdx.ElementID("81bcacb3a43392d2"): {
						PackageSPDXIdentifier:     spdx.ElementID("81bcacb3a43392d2"),
						PackageName:               "actionpack",
						PackageVersion:            "7.0.1",
						PackageLicenseConcluded:   "NONE",
						PackageLicenseDeclared:    "NONE",
						IsFilesAnalyzedTagPresent: true,
					},
				},
				UnpackagedFiles: nil,
				OtherLicenses:   nil,
				Relationships:   nil,
				Annotations:     nil,
				Reviews:         nil,
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
			wantSBOM: &spdx.Document2_2{
				CreationInfo: &spdx.CreationInfo2_2{
					SPDXVersion:                "SPDX-2.2",
					DataLicense:                "CC0-1.0",
					SPDXIdentifier:             "DOCUMENT",
					DocumentName:               "masahiro331/CVE-2021-41098",
					DocumentNamespace:          "http://aquasecurity.github.io/trivy/filesystem/masahiro331/CVE-2021-41098-3ff14136-e09f-4df9-80ea-000000000001",
					CreatorOrganizations:       []string{"aquasecurity"},
					CreatorTools:               []string{"trivy"},
					Created:                    "2021-08-25T12:20:30.000000005Z",
					ExternalDocumentReferences: map[string]spdx.ExternalDocumentRef2_2{},
				},
				Packages: map[spdx.ElementID]*spdx.Package2_2{
					spdx.ElementID("2540a9d087ba8509"): {
						PackageSPDXIdentifier:     spdx.ElementID("2540a9d087ba8509"),
						PackageName:               "actioncable",
						PackageVersion:            "6.1.4.1",
						PackageLicenseConcluded:   "NONE",
						PackageLicenseDeclared:    "NONE",
						IsFilesAnalyzedTagPresent: true,
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
			wantSBOM: &spdx.Document2_2{
				CreationInfo: &spdx.CreationInfo2_2{
					SPDXVersion:                "SPDX-2.2",
					DataLicense:                "CC0-1.0",
					SPDXIdentifier:             "DOCUMENT",
					DocumentName:               "test-aggregate",
					DocumentNamespace:          "http://aquasecurity.github.io/trivy/repository/test-aggregate-3ff14136-e09f-4df9-80ea-000000000001",
					CreatorOrganizations:       []string{"aquasecurity"},
					CreatorTools:               []string{"trivy"},
					Created:                    "2021-08-25T12:20:30.000000005Z",
					ExternalDocumentReferences: map[string]spdx.ExternalDocumentRef2_2{},
				},
				Packages: map[spdx.ElementID]*spdx.Package2_2{
					spdx.ElementID("932072222bf5ccd6"): {
						PackageSPDXIdentifier:     spdx.ElementID("932072222bf5ccd6"),
						PackageName:               "ruby-typeprof",
						PackageVersion:            "0.20.1",
						PackageLicenseConcluded:   "MIT",
						PackageLicenseDeclared:    "MIT",
						IsFilesAnalyzedTagPresent: true,
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
			wantSBOM: &spdx.Document2_2{
				CreationInfo: &spdx.CreationInfo2_2{
					SPDXVersion:                "SPDX-2.2",
					DataLicense:                "CC0-1.0",
					SPDXIdentifier:             "DOCUMENT",
					DocumentName:               "empty/path",
					DocumentNamespace:          "http://aquasecurity.github.io/trivy/filesystem/empty/path-3ff14136-e09f-4df9-80ea-000000000001",
					CreatorOrganizations:       []string{"aquasecurity"},
					CreatorTools:               []string{"trivy"},
					Created:                    "2021-08-25T12:20:30.000000005Z",
					ExternalDocumentReferences: map[string]spdx.ExternalDocumentRef2_2{},
				},
				Packages: nil,
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
			writer := reportSpdx.NewWriter(output, "dev", "spdx-json", reportSpdx.WithClock(clock), reportSpdx.WithNewUUID(newUUID))

			err := writer.Write(tc.inputReport)
			require.NoError(t, err)

			got, err := jsonloader.Load2_2(output)
			require.NoError(t, err)

			assert.Equal(t, *tc.wantSBOM, *got)
		})
	}
}
