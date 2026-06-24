package scan_test

import (
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/local"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	tTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

func TestScanner_ScanArtifact(t *testing.T) {
	type args struct {
		options tTypes.ScanOptions
	}
	tests := []struct {
		name      string
		args      args
		imagePath string
		fixtures  []string
		want      tTypes.Report
		wantErr   string
	}{
		{
			name: "happy path",
			args: args{
				options: tTypes.ScanOptions{
					PkgTypes:            []string{"os"},
					Scanners:            tTypes.Scanners{tTypes.VulnerabilityScanner},
					PkgRelationships:    ftypes.Relationships,
					VulnSeveritySources: []dbTypes.SourceID{"auto"},
				},
			},
			imagePath: "../fanal/test/testdata/alpine-311.tar.gz",
			fixtures:  []string{"local/testdata/fixtures/happy.yaml"},
			want: tTypes.Report{
				SchemaVersion: 2,
				Trivy:         tTypes.TrivyInfo{Version: "dev"},
				CreatedAt:     time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC),
				ArtifactID:    "sha256:574abdaf07824449b1277ec1e7e67659cc869bbf97fd95447812b55644350a21", // hash(ImageID:index.docker.io/library/alpine) from RepoTag alpine:3.11
				ArtifactName:  "../fanal/test/testdata/alpine-311.tar.gz",
				ArtifactType:  ftypes.TypeContainerImage,
				ReportID:      "017b7d41-e09f-7000-80ea-000000000001",
				Metadata: tTypes.Metadata{
					Size: 5861888,
					OS: &ftypes.OS{
						Family:   "alpine",
						Name:     "3.11.5",
						Eosl:     false,
						Extended: false,
					},
					ImageID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					DiffIDs: []string{
						"sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
					},
					RepoTags: []string{"alpine:3.11"},
					Layers: ftypes.Layers{
						{
							Size:   5861888,
							DiffID: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
						},
					},
					Reference: testutil.MustParseReference(t, "alpine:3.11"),
					ImageConfig: v1.ConfigFile{
						Architecture:  "amd64",
						Container:     "fb71ddde5f6411a82eb056a9190f0cc1c80d7f77a8509ee90a2054428edb0024",
						Created:       v1.Time{Time: time.Date(2020, 3, 23, 21, 19, 34, 196162891, time.UTC)},
						DockerVersion: "18.09.7",
						History: []v1.History{
							{
								Created:    v1.Time{Time: time.Date(2020, 3, 23, 21, 19, 34, 27725872, time.UTC)},
								CreatedBy:  "/bin/sh -c #(nop) ADD file:0c4555f363c2672e350001f1293e689875a3760afe7b3f9146886afe67121cba in / ",
								EmptyLayer: false,
							},
							{
								Created:    v1.Time{Time: time.Date(2020, 3, 23, 21, 19, 34, 196162891, time.UTC)},
								CreatedBy:  "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
								EmptyLayer: true,
							},
						},
						OS: "linux",
						RootFS: v1.RootFS{
							Type: "layers",
							DiffIDs: []v1.Hash{
								{
									Algorithm: "sha256",
									Hex:       "beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
								},
							},
						},
						Config: v1.Config{
							Cmd:         []string{"/bin/sh"},
							Env:         []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
							Image:       "sha256:74df73bb19fbfc7fb5ab9a8234b3d98ee2fb92df5b824496679802685205ab8c",
							ArgsEscaped: true,
						},
					},
				},
				Results: tTypes.Results{
					{
						Target: "../fanal/test/testdata/alpine-311.tar.gz (alpine 3.11.5)",
						Class:  tTypes.ClassOSPkg,
						Type:   "alpine",
						Vulnerabilities: []tTypes.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-9999",
								PkgName:          "musl",
								PkgID:            "musl@1.1.24-r2",
								InstalledVersion: "1.1.24-r2",
								FixedVersion:     "1.2.4",
								Status:           dbTypes.StatusFixed,
								Layer: ftypes.Layer{
									DiffID: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
								},
								PrimaryURL:  "https://avd.aquasec.com/nvd/cve-2020-9999",
								Fingerprint: "sha256:36d448cc18b4acd7ccc868fc1865f7dc97694d1e7e4fa55cfabec91990866926", // hash(sha256:574abdaf07824449b1277ec1e7e67659cc869bbf97fd95447812b55644350a21:../fanal/test/testdata/alpine-311.tar.gz (alpine 3.11.5):musl@1.1.24-r2:CVE-2020-9999)
								PkgIdentifier: ftypes.PkgIdentifier{
									UID: "4cdbcc57baa49752",
									PURL: &packageurl.PackageURL{
										Type:      "apk",
										Namespace: "alpine",
										Name:      "musl",
										Version:   "1.1.24-r2",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "arch",
												Value: "x86_64",
											},
											{
												Key:   "distro",
												Value: "3.11.5",
											},
										},
									},
								},
								Vulnerability: dbTypes.Vulnerability{
									Title:       "dos",
									Description: "dos vulnerability",
									Severity:    "HIGH",
								},
							},
							{
								VulnerabilityID:  "CVE-2020-9999",
								PkgName:          "musl-utils",
								PkgID:            "musl-utils@1.1.24-r2",
								InstalledVersion: "1.1.24-r2",
								FixedVersion:     "1.2.4",
								Status:           dbTypes.StatusFixed,
								Layer: ftypes.Layer{
									DiffID: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
								},
								PrimaryURL:  "https://avd.aquasec.com/nvd/cve-2020-9999",
								Fingerprint: "sha256:5b28a2608ccc60c031066a4809cdb5c4ed7eb331e1136b413883c562a7e7aa55", // hash(sha256:574abdaf07824449b1277ec1e7e67659cc869bbf97fd95447812b55644350a21:../fanal/test/testdata/alpine-311.tar.gz (alpine 3.11.5):musl-utils@1.1.24-r2:CVE-2020-9999)
								PkgIdentifier: ftypes.PkgIdentifier{
									UID: "9cb69455d0f6ae6a",
									PURL: &packageurl.PackageURL{
										Type:      "apk",
										Namespace: "alpine",
										Name:      "musl-utils",
										Version:   "1.1.24-r2",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "arch",
												Value: "x86_64",
											},
											{
												Key:   "distro",
												Value: "3.11.5",
											},
										},
									},
								},
								Vulnerability: dbTypes.Vulnerability{
									Title:       "dos",
									Description: "dos vulnerability",
									Severity:    "HIGH",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "sad path: broken database",
			args: args{
				options: tTypes.ScanOptions{
					PkgTypes:         []string{"os"},
					Scanners:         tTypes.Scanners{tTypes.VulnerabilityScanner},
					PkgRelationships: ftypes.Relationships,
				},
			},
			imagePath: "../fanal/test/testdata/alpine-311.tar.gz",
			fixtures:  []string{"local/testdata/fixtures/sad.yaml"},
			wantErr:   "failed to detect vulnerabilities",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID v7 for testing
			uuid.SetFakeUUIDV7(t, "017b7d41-e09f-7000-80ea-%012d")

			// Initialize DB
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			// Load test image
			img, err := image.NewArchiveImage(tt.imagePath)
			require.NoError(t, err)

			// Create artifact
			c := cache.NewMemoryCache()
			artifact, err := image2.NewArtifact(img, c, artifact.Option{})
			require.NoError(t, err)

			// Create scanner
			applier := applier.NewApplier(c)
			scanner := local.NewService(applier, ospkg.NewScanner(), langpkg.NewScanner(), vulnerability.NewClient(db.Config{}))
			s := scan.NewService(scanner, artifact)

			ctx := clock.With(t.Context(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
			got, err := s.ScanArtifact(ctx, tt.args.options)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			for i := range got.Results {
				got.Results[i].Packages = nil
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestService_generateArtifactID(t *testing.T) {
	tests := []struct {
		name         string
		artifactInfo artifact.Reference
		want         string
	}{
		{
			name: "container image with valid reference",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy:latest",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy:latest"),
				},
			},
			want: "sha256:58a3381def2cec86309c94be4fbeaca4b6c0231743ed1df9b0bea883a33cdebb",
		},
		{
			name: "same image with different tag should have same artifact ID",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy:v0.65.0",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy:v0.65.0"),
				},
			},
			want: "sha256:58a3381def2cec86309c94be4fbeaca4b6c0231743ed1df9b0bea883a33cdebb",
		},
		{
			name: "different repository should have different artifact ID",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aqua-sec/trivy:v0.65.0",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "ghcr.io/aqua-sec/trivy:v0.65.0"),
				},
			},
			want: "sha256:bf73a838ae6a9d9c3018fbc7b628741f3be920b75c011a49c0b192736eb789b1",
		},
		{
			name: "different registry should have different artifact ID",
			artifactInfo: artifact.Reference{
				Name: "docker.io/aquasecurity/trivy:v0.65.0",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "docker.io/aquasecurity/trivy:v0.65.0"),
				},
			},
			want: "sha256:dcba426e1fbd6e7fda125be3b9a2507ce3da2c7954c2edbf0e06e34d7f0ca22f",
		},
		{
			name: "docker.io implicit (no registry)",
			artifactInfo: artifact.Reference{
				Name: "aquasecurity/trivy:latest",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "aquasecurity/trivy:latest"),
				},
			},
			want: "sha256:dcba426e1fbd6e7fda125be3b9a2507ce3da2c7954c2edbf0e06e34d7f0ca22f",
		},
		{
			name: "docker.io official image",
			artifactInfo: artifact.Reference{
				Name: "alpine:3.10",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:alpine123",
					Reference: testutil.MustParseReference(t, "alpine:3.10"),
				},
			},
			want: "sha256:56de33d7ec6a1f832c9a7b2a26b1870efe79198e1c13ac645d43798c90954bb5",
		},
		{
			name: "localhost with port",
			artifactInfo: artifact.Reference{
				Name: "localhost:5000/myapp:latest",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:local123",
					Reference: testutil.MustParseReference(t, "localhost:5000/myapp:latest"),
				},
			},
			want: "sha256:7cbf1bbde2285bac7c810fb76da5b0476d284f320f50b913987d6fc9226dc3e3",
		},
		{
			name: "multi-level repository",
			artifactInfo: artifact.Reference{
				Name: "gcr.io/my-org/my-team/my-app:v1.0.0",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:gcr123",
					Reference: testutil.MustParseReference(t, "gcr.io/my-org/my-team/my-app:v1.0.0"),
				},
			},
			want: "sha256:edb01f579a800df17687439f1115bf4ced7bb977aa6afd468675ec56145a530c",
		},
		{
			name: "same image with different digest should have same artifact ID",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:abc123",
					Reference: testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000"),
				},
			},
			want: "sha256:58a3381def2cec86309c94be4fbeaca4b6c0231743ed1df9b0bea883a33cdebb",
		},
		{
			name: "image with digest (no reference)",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy@sha256:abc123",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID: "sha256:abc123",
					// No reference for digest case (empty)
				},
			},
			want: "sha256:abc123",
		},
		{
			name: "container image with no image ID",
			artifactInfo: artifact.Reference{
				Name: "ghcr.io/aquasecurity/trivy:latest",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID: "",
					// No reference
				},
			},
			want: "",
		},
		{
			name: "container image with tar archive (uses RepoTag)",
			artifactInfo: artifact.Reference{
				Name: "../fanal/test/testdata/alpine-311.tar.gz",
				Type: ftypes.TypeContainerImage,
				ImageMetadata: artifact.ImageMetadata{
					ID:        "sha256:fallback123",
					Reference: testutil.MustParseReference(t, "alpine:3.11"),
				},
			},
			want: "sha256:a840c3e6bbadd213fee8cf6e4c32082f06541b8792a929fd373a57e5af0e8fa5",
		},
		{
			name: "repository with URL and commit",
			artifactInfo: artifact.Reference{
				Name: "myrepo",
				Type: ftypes.TypeRepository,
				RepoMetadata: artifact.RepoMetadata{
					RepoURL: "https://github.com/aquasecurity/trivy",
					Commit:  "abc123def456",
				},
			},
			want: "sha256:e23a8c4bae6c00f26ebf52d59e70ddfbbf5b2916d089239c3224f7f06371af98",
		},
		{
			name: "repository with only commit",
			artifactInfo: artifact.Reference{
				Name: "/path/to/local/repo",
				Type: ftypes.TypeRepository,
				RepoMetadata: artifact.RepoMetadata{
					Commit: "abc123def456",
				},
			},
			want: "sha256:9183de2823d60a525ed7aeabdb2cda775cba82dd5da0e94bb2fbba779ad399a7",
		},
		{
			name: "repository without commit",
			artifactInfo: artifact.Reference{
				Name: "myrepo",
				Type: ftypes.TypeRepository,
				RepoMetadata: artifact.RepoMetadata{
					RepoURL: "https://github.com/aquasecurity/trivy",
				},
			},
			want: "",
		},
		{
			name: "filesystem scan",
			artifactInfo: artifact.Reference{
				Name: "/some/path",
				Type: ftypes.TypeFilesystem,
			},
			want: "",
		},
		{
			name: "unknown type",
			artifactInfo: artifact.Reference{
				Name: "something",
				Type: "unknown",
			},
			want: "",
		},
	}

	s := scan.Service{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.GenerateArtifactID(tt.artifactInfo)
			assert.Equal(t, tt.want, got)
		})
	}
}
