package scanner

import (
	"context"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	tTypes "github.com/aquasecurity/trivy/pkg/types"
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
				CreatedAt:     time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC),
				ArtifactName:  "../fanal/test/testdata/alpine-311.tar.gz",
				ArtifactType:  artifact.TypeContainerImage,
				Metadata: tTypes.Metadata{
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
								PrimaryURL: "https://avd.aquasec.com/nvd/cve-2020-9999",
								PkgIdentifier: ftypes.PkgIdentifier{
									UID: "7503855b66ad3a67",
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
								PrimaryURL: "https://avd.aquasec.com/nvd/cve-2020-9999",
								PkgIdentifier: ftypes.PkgIdentifier{
									UID: "69fdae5fbcfe9992",
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
			scanner := local.NewScanner(applier, ospkg.NewScanner(), langpkg.NewScanner(), vulnerability.NewClient(db.Config{}))
			s := NewScanner(scanner, artifact)

			ctx := clock.With(context.Background(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
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
