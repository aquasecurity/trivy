package applier_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestApplyLayers(t *testing.T) {
	tests := []struct {
		name        string
		inputLayers []types.BlobInfo
		want        types.ArtifactDetail
	}{
		{
			name: "happy path",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 1,
					Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					OS: types.OS{
						Family: "alpine",
						Name:   "3.10",
					},
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []types.Package{
								{
									Name:    "openssl",
									Version: "1.2.3",
									Release: "4.5.6",
								},
							},
						},
					},
					Applications: []types.Application{
						{
							Type:     types.Bundler,
							FilePath: "app/Gemfile.lock",
							Libraries: []types.Package{
								{
									Name:    "gemlibrary1",
									Version: "1.2.3",
								},
							},
						},
						{
							Type:     types.Composer,
							FilePath: "app/composer.lock",
							Libraries: []types.Package{
								{
									Name:    "phplibrary1",
									Version: "6.6.6",
								},
							},
						},
						{
							Type:     types.GemSpec,
							FilePath: "usr/local/bundle/specifications/gon-6.3.2.gemspec",
							Libraries: []types.Package{
								{
									Name:     "gon",
									Version:  "6.3.2",
									FilePath: "usr/local/bundle/specifications/gon-6.3.2.gemspec",
								},
							},
						},
					},
				},
				{
					SchemaVersion: 1,
					Digest:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []types.Package{
								{
									Name:    "openssl",
									Version: "1.2.3",
									Release: "4.5.6",
								},
								{ // added
									Name:    "musl",
									Version: "1.2.4",
									Release: "4.5.7",
								},
							},
						},
					},
					WhiteoutFiles: []string{"app/composer.lock"},
				},
				{
					SchemaVersion: 1,
					Digest:        "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []types.Package{
								{
									Name:    "openssl",
									Version: "1.2.3",
									Release: "4.5.6",
								},
								{
									Name:    "musl",
									Version: "1.2.4",
									Release: "4.5.8", // updated
								},
							},
						},
					},
					Applications: []types.Application{
						{
							Type:     types.GemSpec,
							FilePath: "var/lib/gems/2.5.0/specifications/activesupport-6.0.2.1.gemspec",
							Libraries: []types.Package{
								{
									Name:     "activesupport",
									Version:  "6.0.2.1",
									FilePath: "var/lib/gems/2.5.0/specifications/activesupport-6.0.2.1.gemspec",
								},
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family: "alpine",
					Name:   "3.10",
				},
				Packages: []types.Package{
					{
						Name:    "musl",
						Version: "1.2.4",
						Release: "4.5.8",
						Layer: types.Layer{
							Digest: "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
					{
						Name:    "openssl",
						Version: "1.2.3",
						Release: "4.5.6",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
				},
				Applications: []types.Application{
					{
						Type: types.GemSpec,
						Libraries: []types.Package{
							{
								Name:     "activesupport",
								Version:  "6.0.2.1",
								FilePath: "var/lib/gems/2.5.0/specifications/activesupport-6.0.2.1.gemspec",
								Layer: types.Layer{
									Digest: "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
									DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
								},
							},
							{
								Name:     "gon",
								Version:  "6.3.2",
								FilePath: "usr/local/bundle/specifications/gon-6.3.2.gemspec",
								Layer: types.Layer{
									Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
									DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
								},
							},
						},
					},
					{
						Type:     types.Bundler,
						FilePath: "app/Gemfile.lock",
						Libraries: []types.Package{
							{
								Name:    "gemlibrary1",
								Version: "1.2.3",
								Layer: types.Layer{
									Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
									DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with merging ubuntu version and ESM",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 1,
					Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					OS: types.OS{
						Family:   "ubuntu",
						Extended: true,
					},
				},
				{
					SchemaVersion: 1,
					Digest:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					OS: types.OS{
						Family: "ubuntu",
						Name:   "16.04",
					},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family:   "ubuntu",
					Name:     "16.04",
					Extended: true,
				},
			},
		},
		{
			name: "happy path with removed and updated lockfile",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 1,
					Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					OS: types.OS{
						Family: "alpine",
						Name:   "3.10",
					},
					Applications: []types.Application{
						{
							Type:     types.Bundler,
							FilePath: "app/Gemfile.lock",
							Libraries: []types.Package{
								{
									Name:    "rails",
									Version: "5.0.0",
								},
								{
									Name:    "rack",
									Version: "4.0.0",
								},
							},
						},
						{
							Type:     types.Composer,
							FilePath: "app/composer.lock",
							Libraries: []types.Package{
								{
									Name:    "phplibrary1",
									Version: "6.6.6",
								},
							},
						},
						{
							Type:     types.GemSpec,
							FilePath: "var/lib/gems/2.5.0/specifications/activesupport-6.0.2.1.gemspec",
							Libraries: []types.Package{
								{
									Name:     "activesupport",
									Version:  "6.0.2.1",
									FilePath: "var/lib/gems/2.5.0/specifications/activesupport-6.0.2.1.gemspec",
								},
							},
						},
					},
				},
				{
					SchemaVersion: 1,
					Digest:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					Applications: []types.Application{
						{
							Type:     types.Bundler,
							FilePath: "app/Gemfile.lock",
							Libraries: []types.Package{
								{
									Name:    "rails",
									Version: "6.0.0",
								},
								{
									Name:    "rack",
									Version: "4.0.0",
								},
							},
						},
						{
							Type:     "composer",
							FilePath: "app/composer2.lock",
							Libraries: []types.Package{
								{
									Name:    "phplibrary1",
									Version: "6.6.6",
								},
							},
						},
					},
					WhiteoutFiles: []string{
						"app/composer.lock",
						"var/lib/gems/2.5.0/specifications/activesupport-6.0.2.1.gemspec",
					},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family: "alpine",
					Name:   "3.10",
				},
				Applications: []types.Application{
					{
						Type:     types.Bundler,
						FilePath: "app/Gemfile.lock",
						Libraries: []types.Package{
							{
								Name:    "rack",
								Version: "4.0.0",
								Layer: types.Layer{
									Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
									DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
								},
							},
							{
								Name:    "rails",
								Version: "6.0.0",
								Layer: types.Layer{
									Digest: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
									DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
								},
							},
						},
					},
					{
						Type:     types.Composer,
						FilePath: "app/composer2.lock",
						Libraries: []types.Package{
							{
								Name:    "phplibrary1",
								Version: "6.6.6",
								Layer: types.Layer{
									Digest: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
									DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with removed and updated secret",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 2,
					Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					CreatedBy:     "Line_1",
					Secrets: []types.Secret{
						{
							FilePath: "usr/secret.txt",
							Findings: []types.SecretFinding{
								{
									RuleID:    "aws-access-key-id",
									Category:  "AWS",
									Severity:  "CRITICAL",
									Title:     "AWS Access Key ID",
									StartLine: 1,
									EndLine:   1,
									Match:     "AWS_ACCESS_KEY_ID=********************",
									Code: types.Code{
										Lines: []types.Line{
											{
												Number:      1,
												Content:     "AWS_ACCESS_KEY_ID=********************",
												IsCause:     true,
												Highlighted: "AWS_ACCESS_KEY_ID=********************",
												FirstCause:  true,
												LastCause:   true,
											},
										},
									},
								},
							},
						},
					},
				},
				{
					SchemaVersion: 2,
					Digest:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					CreatedBy:     "Line_2",
					Secrets: []types.Secret{
						{
							FilePath: "usr/secret.txt",
							Findings: []types.SecretFinding{
								{
									RuleID:    "github-pat",
									Category:  "GitHub",
									Severity:  "CRITICAL",
									Title:     "GitHub Personal Access Token",
									StartLine: 1,
									EndLine:   1,
									Match:     "GITHUB_PAT=****************************************",
									Code: types.Code{
										Lines: []types.Line{
											{
												Number:      1,
												Content:     "GITHUB_PAT=****************************************",
												IsCause:     true,
												Highlighted: "GITHUB_PAT=****************************************",
												FirstCause:  true,
												LastCause:   true,
											},
										},
									},
								},
								{
									RuleID:    "aws-access-key-id",
									Category:  "AWS",
									Severity:  "CRITICAL",
									Title:     "AWS Access Key ID",
									StartLine: 2,
									EndLine:   2,
									Match:     "AWS_ACCESS_KEY_ID=********************",
									Code: types.Code{
										Lines: []types.Line{
											{
												Number:      1,
												Content:     "AWS_ACCESS_KEY_ID=********************",
												IsCause:     true,
												Highlighted: "AWS_ACCESS_KEY_ID=********************",
												FirstCause:  true,
												LastCause:   true,
											},
										},
									},
								},
							},
						},
					},
				},
				{
					SchemaVersion: 2,
					Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					CreatedBy:     "Line_3",
					WhiteoutFiles: []string{
						"usr/secret.txt",
					},
				},
			},
			want: types.ArtifactDetail{
				Secrets: []types.Secret{
					{
						FilePath: "usr/secret.txt",
						Findings: []types.SecretFinding{
							{
								RuleID:    "github-pat",
								Category:  "GitHub",
								Severity:  "CRITICAL",
								Title:     "GitHub Personal Access Token",
								StartLine: 1,
								EndLine:   1,
								Match:     "GITHUB_PAT=****************************************",
								Layer: types.Layer{
									Digest:    "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
									DiffID:    "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
									CreatedBy: "Line_2",
								},
								Code: types.Code{
									Lines: []types.Line{
										{
											Number:      1,
											Content:     "GITHUB_PAT=****************************************",
											IsCause:     true,
											Highlighted: "GITHUB_PAT=****************************************",
											FirstCause:  true,
											LastCause:   true,
										},
									},
								},
							},
							{
								RuleID:    "aws-access-key-id",
								Category:  "AWS",
								Severity:  "CRITICAL",
								Title:     "AWS Access Key ID",
								StartLine: 2,
								EndLine:   2,
								Match:     "AWS_ACCESS_KEY_ID=********************",
								Layer: types.Layer{
									Digest:    "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
									DiffID:    "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
									CreatedBy: "Line_2",
								},
								Code: types.Code{
									Lines: []types.Line{
										{
											Number:      1,
											Content:     "AWS_ACCESS_KEY_ID=********************",
											IsCause:     true,
											Highlighted: "AWS_ACCESS_KEY_ID=********************",
											FirstCause:  true,
											LastCause:   true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with status.d and opaque dirs without the trailing slash",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 1,
					Digest:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					OS: types.OS{
						Family: "debian",
						Name:   "8",
					},
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/dpkg/status.d/openssl",
							Packages: []types.Package{
								{
									Name:    "openssl",
									Version: "1.2.3",
									Release: "4.5.6",
								},
							},
						},
					},
					Applications: []types.Application{
						{
							Type:     "composer",
							FilePath: "app/composer.lock",
							Libraries: []types.Package{
								{
									Name:    "phplibrary1",
									Version: "6.6.6",
								},
							},
						},
					},
					Licenses: []types.LicenseFile{
						{
							Type:     types.LicenseTypeDpkg,
							FilePath: "usr/share/doc/openssl/copyright",
							Findings: []types.LicenseFinding{
								{Name: "OpenSSL"},
							},
							PkgName: "openssl",
						},
					},
				},
				{
					SchemaVersion: 1,
					Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/dpkg/status.d/libc",
							Packages: []types.Package{
								{
									Name:    "libc",
									Version: "1.2.4",
									Release: "4.5.7",
								},
							},
						},
					},
					Licenses: []types.LicenseFile{
						{
							Type:     types.LicenseTypeDpkg,
							FilePath: "usr/share/doc/libc/copyright",
							Findings: []types.LicenseFinding{
								{Name: "GPL-2"},
							},
							PkgName: "libc",
						},
					},
					OpaqueDirs: []string{"app"},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family: "debian",
					Name:   "8",
				},
				Packages: []types.Package{
					{
						Name:     "libc",
						Version:  "1.2.4",
						Release:  "4.5.7",
						Licenses: []string{"GPL-2"},
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
					{
						Name:     "openssl",
						Version:  "1.2.3",
						Release:  "4.5.6",
						Licenses: []string{"OpenSSL"},
						Layer: types.Layer{
							Digest: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
				},
			},
		},
		{
			name: "happy path, opaque dirs with the trailing slash",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 1,
					Digest:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					Applications: []types.Application{
						{
							Type:     "composer",
							FilePath: "app/composer.lock",
							Libraries: []types.Package{
								{
									Name:    "phplibrary1",
									Version: "6.6.6",
								},
							},
						},
					},
				},
				{
					SchemaVersion: 1,
					Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					OpaqueDirs:    []string{"app/"},
				},
			},
			want: types.ArtifactDetail{},
		},
		{
			name: "happy path with Red Hat content sets",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 1,
					Digest:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					OS: types.OS{
						Family: "redhat",
						Name:   "8",
					},
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/rpm/Packages",
							Packages: []types.Package{
								{
									Name:    "openssl",
									Version: "1.2.3",
									Release: "4",
								},
							},
						},
					},
				},
				{
					SchemaVersion: 1,
					Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					BuildInfo: &types.BuildInfo{
						ContentSets: []string{
							"rhel-8-for-x86_64-baseos-rpms",
							"rhel-8-for-x86_64-appstream-rpms",
						},
					},
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/rpm/Packages",
							Packages: []types.Package{
								{
									Name:    "openssl",
									Version: "1.2.3",
									Release: "4",
								},
								{
									Name:    "libc",
									Version: "1.2.4",
									Release: "5",
								},
							},
						},
					},
				},
				{
					SchemaVersion: 1,
					Digest:        "sha256:a64e5f34c33ed4c5121498e721e24d95dae2c9599bee4aa6d07850702b401406",
					DiffID:        "sha256:0abd3f2c73de6f02e033f410590111f9339b9500dc07270234f283f2d9a2694b",
					BuildInfo: &types.BuildInfo{
						Nvr:  "3scale-amp-apicast-gateway-container-1.11-1",
						Arch: "x86_64",
					},
				},
				{
					SchemaVersion: 1,
					Digest:        "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/rpm/Packages",
							Packages: []types.Package{
								{
									Name:    "openssl",
									Version: "1.2.3",
									Release: "4",
								},
								{
									Name:    "libc",
									Version: "1.2.4",
									Release: "5",
								},
								{
									Name:    "bash",
									Version: "5.6.7",
									Release: "8",
								},
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family: "redhat",
					Name:   "8",
				},
				Packages: []types.Package{
					{
						Name:    "bash",
						Version: "5.6.7",
						Release: "8",
						Layer: types.Layer{
							Digest: "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
						BuildInfo: &types.BuildInfo{
							Nvr:  "3scale-amp-apicast-gateway-container-1.11-1",
							Arch: "x86_64",
						},
					},
					{
						Name:    "libc",
						Version: "1.2.4",
						Release: "5",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
						BuildInfo: &types.BuildInfo{
							ContentSets: []string{
								"rhel-8-for-x86_64-baseos-rpms",
								"rhel-8-for-x86_64-appstream-rpms",
							},
						},
					},
					{
						Name:    "openssl",
						Version: "1.2.3",
						Release: "4",
						Layer: types.Layer{
							Digest: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
						BuildInfo: &types.BuildInfo{
							ContentSets: []string{
								"rhel-8-for-x86_64-baseos-rpms",
								"rhel-8-for-x86_64-appstream-rpms",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applier.ApplyLayers(tt.inputLayers)
			sort.Sort(got.Packages)
			sort.Slice(got.Applications, func(i, j int) bool {
				return got.Applications[i].FilePath < got.Applications[j].FilePath
			})
			for _, app := range got.Applications {
				sort.Slice(app.Libraries, func(i, j int) bool {
					return app.Libraries[i].Name < app.Libraries[j].Name
				})
			}
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}
