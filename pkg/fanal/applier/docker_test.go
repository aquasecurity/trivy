package applier_test

import (
	"sort"
	"testing"

	"github.com/package-url/packageurl-go"
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
							Packages: types.Packages{
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
							Packages: types.Packages{
								{
									Name:    "gemlibrary1",
									Version: "1.2.3",
								},
							},
						},
						{
							Type:     types.Composer,
							FilePath: "app/composer.lock",
							Packages: types.Packages{
								{
									Name:    "phplibrary1",
									Version: "6.6.6",
								},
							},
						},
						{
							Type:     types.GemSpec,
							FilePath: "usr/local/bundle/specifications/gon-6.3.2.gemspec",
							Packages: types.Packages{
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
							Packages: types.Packages{
								{
									Name:    "openssl",
									Version: "1.2.3",
									Release: "4.5.6",
								},
								{
									// added
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
							Packages: types.Packages{
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
							Packages: types.Packages{
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
				Packages: types.Packages{
					{
						Name:    "musl",
						Version: "1.2.4",
						Release: "4.5.8",
						Identifier: types.PkgIdentifier{
							UID: "108c0f3943d7bc9",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeApk,
								Namespace: "alpine",
								Name:      "musl",
								Version:   "1.2.4-4.5.8",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "3.10",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
					{
						Name:    "openssl",
						Version: "1.2.3",
						Release: "4.5.6",
						Identifier: types.PkgIdentifier{
							UID: "9d77cb17d1fc8736",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeApk,
								Namespace: "alpine",
								Name:      "openssl",
								Version:   "1.2.3-4.5.6",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "3.10",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
				},
				Applications: []types.Application{
					{
						Type: types.GemSpec,
						Packages: types.Packages{
							{
								Name:     "activesupport",
								Version:  "6.0.2.1",
								FilePath: "var/lib/gems/2.5.0/specifications/activesupport-6.0.2.1.gemspec",
								Layer: types.Layer{
									Digest: "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
									DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
								},
								Identifier: types.PkgIdentifier{
									UID: "b3549e98a3094a66",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "activesupport",
										Version: "6.0.2.1",
									},
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
								Identifier: types.PkgIdentifier{
									UID: "f27f3b46e09fc2e2",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "gon",
										Version: "6.3.2",
									},
								},
							},
						},
					},
					{
						Type:     types.Bundler,
						FilePath: "app/Gemfile.lock",
						Packages: types.Packages{
							{
								Name:    "gemlibrary1",
								Version: "1.2.3",
								Layer: types.Layer{
									Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
									DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
								},
								Identifier: types.PkgIdentifier{
									UID: "a3363562b587cfa2",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "gemlibrary1",
										Version: "1.2.3",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with duplicate of debian packages",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 2,
					DiffID:        "sha256:96e320b34b5478d8b369ca43ffaa88ff6dd9499ec72b792ca21b1e8b0c55670f",
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/dpkg/status.d/libssl1",
							Packages: types.Packages{
								{
									ID:      "libssl1.1@1.1.1n-0+deb11u3",
									Name:    "libssl1.1",
									Version: "1.1.1n",
									Release: "0+deb11u3",
								},
							},
						},
					},
				},
				{
					SchemaVersion: 2,
					DiffID:        "sha256:5e087d956f3e62bd034dd0712bc4cbef8fda55fba0b11a7d0564f294887c7079",
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/dpkg/status.d/libssl1.1",
							Packages: types.Packages{
								{
									ID:      "libssl1.1@1.1.1n-0+deb11u3",
									Name:    "libssl1.1",
									Version: "1.1.1n",
									Release: "0+deb11u3",
								},
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				Packages: types.Packages{
					{
						ID:      "libssl1.1@1.1.1n-0+deb11u3",
						Name:    "libssl1.1",
						Version: "1.1.1n",
						Release: "0+deb11u3",
						Identifier: types.PkgIdentifier{
							UID: "522a5c3b263d1357",
						},
						Layer: types.Layer{
							DiffID: "sha256:96e320b34b5478d8b369ca43ffaa88ff6dd9499ec72b792ca21b1e8b0c55670f",
						},
					},
				},
			},
		},
		{
			name: "happy path with digests in libs/packages (as for SBOM)",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 2,
					OS: types.OS{
						Family: "debian",
						Name:   "11.8",
					},
					PackageInfos: []types.PackageInfo{
						{
							Packages: types.Packages{
								{
									ID:         "adduser@3.118+deb11u1",
									Name:       "adduser",
									Version:    "3.118+deb11u1",
									Arch:       "all",
									SrcName:    "adduser",
									SrcVersion: "3.118+deb11u1",
									Layer: types.Layer{
										Digest: "sha256:e67fdae3559346105027c63e7fb032bba57e62b1fe9f2da23e6fdfb56384e00b",
										DiffID: "sha256:633f5bf471f7595b236a21e62dc60beef321db45916363a02ad5af02d794d497",
									},
								},
							},
						},
					},
					Applications: []types.Application{
						{
							Type: types.PythonPkg,
							Packages: types.Packages{
								{
									Name:    "pip",
									Version: "23.0.1",
									Layer: types.Layer{
										DiffID: "sha256:1def056a3160854c9395aa76282dd62172ec08c18a5fa03bb7d50a777c15ba99",
									},
									FilePath: "usr/local/lib/python3.9/site-packages/pip-23.0.1.dist-info/METADATA",
								},
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family: "debian",
					Name:   "11.8",
				},
				Packages: types.Packages{
					{
						ID:         "adduser@3.118+deb11u1",
						Name:       "adduser",
						Version:    "3.118+deb11u1",
						Arch:       "all",
						SrcName:    "adduser",
						SrcVersion: "3.118+deb11u1",
						Layer: types.Layer{
							Digest: "sha256:e67fdae3559346105027c63e7fb032bba57e62b1fe9f2da23e6fdfb56384e00b",
							DiffID: "sha256:633f5bf471f7595b236a21e62dc60beef321db45916363a02ad5af02d794d497",
						},
						Identifier: types.PkgIdentifier{
							UID: "e984be704d7e13ef",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeDebian,
								Namespace: "debian",
								Name:      "adduser",
								Version:   "3.118+deb11u1",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "arch",
										Value: "all",
									},
									{
										Key:   "distro",
										Value: "debian-11.8",
									},
								},
							},
						},
					},
				},
				Applications: []types.Application{
					{
						Type: types.PythonPkg,
						Packages: types.Packages{
							{
								Name:     "pip",
								Version:  "23.0.1",
								FilePath: "usr/local/lib/python3.9/site-packages/pip-23.0.1.dist-info/METADATA",
								Layer: types.Layer{
									DiffID: "sha256:1def056a3160854c9395aa76282dd62172ec08c18a5fa03bb7d50a777c15ba99",
								},
								Identifier: types.PkgIdentifier{
									UID: "8d8c54cecea3dd33",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypePyPi,
										Name:    "pip",
										Version: "23.0.1",
									},
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
							Packages: types.Packages{
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
							Packages: types.Packages{
								{
									Name:    "phplibrary1",
									Version: "6.6.6",
								},
							},
						},
						{
							Type:     types.GemSpec,
							FilePath: "var/lib/gems/2.5.0/specifications/activesupport-6.0.2.1.gemspec",
							Packages: types.Packages{
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
							Packages: types.Packages{
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
							Packages: types.Packages{
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
						Packages: types.Packages{
							{
								Name:    "rack",
								Version: "4.0.0",
								Layer: types.Layer{
									Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
									DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
								},
								Identifier: types.PkgIdentifier{
									UID: "9744e21755aea0ef",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "rack",
										Version: "4.0.0",
									},
								},
							},
							{
								Name:    "rails",
								Version: "6.0.0",
								Layer: types.Layer{
									Digest: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
									DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
								},
								Identifier: types.PkgIdentifier{
									UID: "7e9712137f044ffe",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "rails",
										Version: "6.0.0",
									},
								},
							},
						},
					},
					{
						Type:     types.Composer,
						FilePath: "app/composer2.lock",
						Packages: types.Packages{
							{
								Name:    "phplibrary1",
								Version: "6.6.6",
								Layer: types.Layer{
									Digest: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
									DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
								},
								Identifier: types.PkgIdentifier{
									UID: "940351428c1fed49",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeComposer,
										Name:    "phplibrary1",
										Version: "6.6.6",
									},
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
							Packages: types.Packages{
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
							Packages: types.Packages{
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
							Packages: types.Packages{
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
				Packages: types.Packages{
					{
						Name:     "libc",
						Version:  "1.2.4",
						Release:  "4.5.7",
						Licenses: []string{"GPL-2"},
						Identifier: types.PkgIdentifier{
							UID: "c3c9ea1442ead294",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeDebian,
								Namespace: "debian",
								Name:      "libc",
								Version:   "1.2.4-4.5.7",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "debian-8",
									},
								},
							},
						},
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
						Identifier: types.PkgIdentifier{
							UID: "9d77cb17d1fc8736",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeDebian,
								Namespace: "debian",
								Name:      "openssl",
								Version:   "1.2.3-4.5.6",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "debian-8",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
				},
			},
		},
		{
			name: "happy path with filling system files for debian packages",
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 2,
					DiffID:        "sha256:cdd7c73923174e45ea648d66996665c288e1b17a0f45efdbeca860f6dafdf731",
					OS: types.OS{
						Family: "ubuntu",
						Name:   "24.04",
					},
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/dpkg/status",
							Packages: types.Packages{
								{
									ID:         "apt@2.4.9",
									Name:       "apt",
									Version:    "2.4.9",
									Arch:       "amd64",
									SrcName:    "apt",
									SrcVersion: "2.4.9",
									InstalledFiles: []string{
										"/etc/apt/apt.conf.d/01-vendor-ubuntu",
										"/etc/apt/apt.conf.d/01autoremove",
										"/etc/apt/auth.conf.d",
										"/etc/apt/keyrings",
									},
								},
							},
						},
					},
				},
				// Install `curl`
				{
					SchemaVersion: 2,
					DiffID:        "sha256:faf30fa9c41c10f93b3b134d7b2c16e07753320393e020c481f0c97d10db067d",
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/dpkg/status",
							Packages: types.Packages{
								{
									ID:         "apt@2.4.9",
									Name:       "apt",
									Version:    "2.4.9",
									Arch:       "amd64",
									SrcName:    "apt",
									SrcVersion: "2.4.9",
								},
								{
									ID:         "curl@8.5.0-2ubuntu10.1",
									Name:       "curl",
									Version:    "8.5.0",
									Release:    "2ubuntu10.1",
									Arch:       "arm64",
									SrcName:    "curl",
									SrcVersion: "8.5.0",
									SrcRelease: "2ubuntu10.1",
									InstalledFiles: []string{
										"/usr/bin/curl",
										"/usr/share/doc/curl/README.Debian",
										"/usr/share/doc/curl/changelog.Debian.gz",
										"/usr/share/doc/curl/copyright",
										"/usr/share/man/man1/curl.1.gz",
										"/usr/share/zsh/vendor-completions/_curl",
									},
								},
							},
						},
					},
				},
				// Upgrade `apt`
				{
					SchemaVersion: 2,
					DiffID:        "sha256:440e26edc0eb9b4fee6e1d40d8af9eb59500d38e25edfc5d5302c55f59394c1e",
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/dpkg/status",
							Packages: types.Packages{
								{
									ID:         "apt@2.4.12",
									Name:       "apt",
									Version:    "2.4.12",
									Arch:       "amd64",
									SrcName:    "apt",
									SrcVersion: "2.4.12",
									InstalledFiles: []string{
										"/etc/apt/apt.conf.d/01-vendor-ubuntu",
										"/etc/apt/apt.conf.d/01autoremove",
										"/etc/apt/auth.conf.d",
										"/etc/apt/keyrings",
										"/usr/share/man/it/man5/sources.list.5.gz",
									},
								},
								{
									ID:         "curl@8.5.0-2ubuntu10.1",
									Name:       "curl",
									Version:    "8.5.0",
									Release:    "2ubuntu10.1",
									Arch:       "arm64",
									SrcName:    "curl",
									SrcVersion: "8.5.0",
									SrcRelease: "2ubuntu10.1",
								},
							},
						},
					},
				},
				// Remove curl
				{
					SchemaVersion: 2,
					DiffID:        "sha256:cb04e1d437de723d8d04bc7df89dc42271530c5f8ea1724c6072e3f0e7d6d38a",
					WhiteoutFiles: []string{
						"usr/bin/curl",
						"usr/share/doc/curl",
						"usr/share/zsh",
						"var/lib/dpkg/info/curl.list",
						"var/lib/dpkg/info/curl.md5sums",
					},
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/dpkg/status",
							Packages: types.Packages{
								{
									ID:         "apt@2.4.12",
									Name:       "apt",
									Version:    "2.4.12",
									Arch:       "amd64",
									SrcName:    "apt",
									SrcVersion: "2.4.12",
								},
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family: "ubuntu",
					Name:   "24.04",
				},
				Packages: types.Packages{
					{
						ID:         "apt@2.4.12",
						Name:       "apt",
						Version:    "2.4.12",
						Arch:       "amd64",
						SrcName:    "apt",
						SrcVersion: "2.4.12",

						Identifier: types.PkgIdentifier{
							UID: "80bc98a8f3159db9",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeDebian,
								Namespace: "ubuntu",
								Name:      "apt",
								Version:   "2.4.12",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "arch",
										Value: "amd64",
									},
									{
										Key:   "distro",
										Value: "ubuntu-24.04",
									},
								},
							},
						},
						Layer: types.Layer{
							DiffID: "sha256:440e26edc0eb9b4fee6e1d40d8af9eb59500d38e25edfc5d5302c55f59394c1e",
						},
						InstalledFiles: []string{
							"/etc/apt/apt.conf.d/01-vendor-ubuntu",
							"/etc/apt/apt.conf.d/01autoremove",
							"/etc/apt/auth.conf.d",
							"/etc/apt/keyrings",
							"/usr/share/man/it/man5/sources.list.5.gz",
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
							Packages: types.Packages{
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
							Packages: types.Packages{
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
							Packages: types.Packages{
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
							Packages: types.Packages{
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
				Packages: types.Packages{
					{
						Name:    "bash",
						Version: "5.6.7",
						Release: "8",
						Identifier: types.PkgIdentifier{
							UID: "3982c06acacff066",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeRPM,
								Namespace: "redhat",
								Name:      "bash",
								Version:   "5.6.7-8",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "redhat-8",
									},
								},
							},
						},
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
						Identifier: types.PkgIdentifier{
							UID: "8a72001605297eac",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeRPM,
								Namespace: "redhat",
								Name:      "libc",
								Version:   "1.2.4-5",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "redhat-8",
									},
								},
							},
						},
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
						Identifier: types.PkgIdentifier{
							UID: "8de1ca1c33881bac",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeRPM,
								Namespace: "redhat",
								Name:      "openssl",
								Version:   "1.2.3-4",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "redhat-8",
									},
								},
							},
						},
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
		{
			name: "same package but different file path", // different hashes
			inputLayers: []types.BlobInfo{
				{
					SchemaVersion: 1,
					Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					Applications: []types.Application{
						{
							Type:     types.Bundler,
							FilePath: "app1/Gemfile.lock",
							Packages: types.Packages{
								{
									Name:    "gemlibrary1",
									Version: "1.2.3",
								},
							},
						},
						{
							Type:     types.Bundler,
							FilePath: "app2/Gemfile.lock",
							Packages: types.Packages{
								{
									Name:    "gemlibrary1",
									Version: "1.2.3",
								},
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				Applications: []types.Application{
					{
						Type:     types.Bundler,
						FilePath: "app1/Gemfile.lock",
						Packages: types.Packages{
							{
								Name:    "gemlibrary1",
								Version: "1.2.3",
								Layer: types.Layer{
									Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
									DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
								},
								Identifier: types.PkgIdentifier{
									UID: "176111c6c0c6488", // different hash
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "gemlibrary1",
										Version: "1.2.3",
									},
								},
							},
						},
					},
					{
						Type:     types.Bundler,
						FilePath: "app2/Gemfile.lock",
						Packages: types.Packages{
							{
								Name:    "gemlibrary1",
								Version: "1.2.3",
								Layer: types.Layer{
									Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
									DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
								},
								Identifier: types.PkgIdentifier{
									UID: "e1416731a0829253", // different hash
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGem,
										Name:    "gemlibrary1",
										Version: "1.2.3",
									},
								},
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
				sort.Sort(app.Packages)
			}
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}
