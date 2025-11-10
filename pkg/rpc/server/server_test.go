package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/cachetest"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/local"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
	"github.com/aquasecurity/trivy/rpc/common"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

func TestScanServer_Scan(t *testing.T) {
	type args struct {
		in *rpcScanner.ScanRequest
	}
	tests := []struct {
		name       string
		args       args
		fixtures   []string
		setUpCache func(t *testing.T) cache.Cache
		want       *rpcScanner.ScanResponse
		wantErr    string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcScanner.ScanRequest{
					Target:     "alpine:3.11",
					ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					BlobIds:    []string{"sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203"},
					Options: &rpcScanner.ScanOptions{
						PkgTypes:            []string{types.PkgTypeOS},
						Scanners:            []string{string(types.VulnerabilityScanner)},
						PkgRelationships:    []string{ftypes.RelationshipUnknown.String()},
						VulnSeveritySources: []string{"auto"},
					},
				},
			},
			fixtures: []string{"../../scan/local/testdata/fixtures/happy.yaml"},
			setUpCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutArtifact(t.Context(), "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a", ftypes.ArtifactInfo{
					SchemaVersion: 1,
				}))

				require.NoError(t, c.PutBlob(t.Context(), "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203", ftypes.BlobInfo{
					SchemaVersion: 1,
					Size:          1000,
					DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
					OS: ftypes.OS{
						Family: "alpine",
						Name:   "3.11.5",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: ftypes.Packages{
								{
									Name:       "musl",
									Version:    "1.1.24-r2",
									SrcName:    "musl",
									SrcVersion: "1.1.24-r2",
								},
							},
						},
					},
				}))

				return c
			},
			want: &rpcScanner.ScanResponse{
				Os: &common.OS{
					Family: "alpine",
					Name:   "3.11.5",
					Eosl:   true,
				},
				Results: []*rpcScanner.Result{
					{
						Target: "alpine:3.11 (alpine 3.11.5)",
						Vulnerabilities: []*common.Vulnerability{
							{
								VulnerabilityId:  "CVE-2020-9999",
								PkgName:          "musl",
								InstalledVersion: "1.1.24-r2",
								FixedVersion:     "1.2.4",
								Severity:         common.Severity_HIGH,
								Layer: &common.Layer{
									DiffId: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
								},
								PrimaryUrl:  "https://avd.aquasec.com/nvd/cve-2020-9999",
								Title:       "dos",
								Description: "dos vulnerability",
								Status:      3,
								PkgIdentifier: &common.PkgIdentifier{
									Purl: "pkg:apk/alpine/musl@1.1.24-r2?distro=3.11.5",
									Uid:  "852936e86971b22e",
								},
								Cvss:           make(map[string]*common.CVSS),
								VendorSeverity: make(map[string]common.Severity),
							},
						},
						Type:  "alpine",
						Class: "os-pkgs",
						Packages: []*common.Package{
							{
								Name:       "musl",
								Version:    "1.1.24-r2",
								SrcName:    "musl",
								SrcVersion: "1.1.24-r2",
								Layer: &common.Layer{
									DiffId: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
								},
								Identifier: &common.PkgIdentifier{
									Purl: "pkg:apk/alpine/musl@1.1.24-r2?distro=3.11.5",
									Uid:  "852936e86971b22e",
								},
							},
						},
					},
				},
				Layers: []*common.Layer{
					{
						Size:   1000,
						DiffId: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
					},
				},
			},
		},
		{
			name: "sad path: broken database",
			args: args{
				in: &rpcScanner.ScanRequest{
					Target:     "alpine:3.11",
					ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					BlobIds:    []string{"sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203"},
					Options: &rpcScanner.ScanOptions{
						PkgTypes:         []string{types.PkgTypeOS},
						Scanners:         []string{string(types.VulnerabilityScanner)},
						PkgRelationships: []string{ftypes.RelationshipUnknown.String()},
					},
				},
			},
			fixtures: []string{"../../scan/local/testdata/fixtures/sad.yaml"},
			setUpCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutArtifact(t.Context(), "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a", ftypes.ArtifactInfo{
					SchemaVersion: 1,
				}))

				require.NoError(t, c.PutBlob(t.Context(), "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203", ftypes.BlobInfo{
					SchemaVersion: 1,
					Digest:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
					DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
					OS: ftypes.OS{
						Family: "alpine",
						Name:   "3.11.5",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: ftypes.Packages{
								{
									Name:       "musl",
									Version:    "1.1.24-r2",
									SrcName:    "musl",
									SrcVersion: "1.1.24-r2",
								},
							},
						},
					},
				}))

				return c
			},
			wantErr: "failed to detect vulnerabilities",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			// Create artifact
			c := cachetest.NewCache(t, tt.setUpCache)

			// Create scanner
			applier := applier.NewApplier(c)
			scanner := local.NewService(applier, ospkg.NewScanner(), langpkg.NewScanner(), vulnerability.NewClient(db.Config{}))
			s := NewScanServer(scanner)

			got, err := s.Scan(t.Context(), tt.args.in)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCacheServer_PutArtifact(t *testing.T) {
	type args struct {
		in *rpcCache.PutArtifactRequest
	}
	tests := []struct {
		name         string
		args         args
		setUpCache   func(t *testing.T) cache.Cache
		wantArtifact cachetest.WantArtifact
		want         *emptypb.Empty
		wantErr      string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcCache.PutArtifactRequest{
					ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ArtifactInfo: &rpcCache.ArtifactInfo{
						SchemaVersion: 1,
						Architecture:  "amd64",
						Created: func() *timestamppb.Timestamp {
							d := time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC)
							t := timestamppb.New(d)
							return t
						}(),
						DockerVersion: "18.09",
						Os:            "linux",
					},
				},
			},
			wantArtifact: cachetest.WantArtifact{
				ID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
				ArtifactInfo: ftypes.ArtifactInfo{
					SchemaVersion: 1,
					Architecture:  "amd64",
					Created:       time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC),
					DockerVersion: "18.09",
					OS:            "linux",
				},
			},
			want: &emptypb.Empty{},
		},
		{
			name: "sad path",
			args: args{
				in: &rpcCache.PutArtifactRequest{
					ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ArtifactInfo: &rpcCache.ArtifactInfo{
						SchemaVersion: 1,
						Created: func() *timestamppb.Timestamp {
							d := time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC)
							t := timestamppb.New(d)
							return t
						}(),
					},
				},
			},
			setUpCache: func(_ *testing.T) cache.Cache {
				return cachetest.NewErrorCache(cachetest.ErrorCacheOptions{
					PutArtifact: true,
				})
			},
			wantErr: "unable to store image info in cache",
		},
		{
			name: "sad path: empty image info",
			args: args{
				in: &rpcCache.PutArtifactRequest{},
			},
			wantErr: "empty image info",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cachetest.NewCache(t, tt.setUpCache)

			s := NewCacheServer(c)
			got, err := s.PutArtifact(t.Context(), tt.args.in)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr, tt.name)
				return
			}
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got)
			cachetest.AssertArtifact(t, c, tt.wantArtifact)
		})
	}
}

func TestCacheServer_PutBlob(t *testing.T) {
	type args struct {
		in *rpcCache.PutBlobRequest
	}
	tests := []struct {
		name       string
		args       args
		setUpCache func(t *testing.T) cache.Cache
		wantBlobs  []cachetest.WantBlob
		want       *emptypb.Empty
		wantErr    string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcCache.PutBlobRequest{
					DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					BlobInfo: &rpcCache.BlobInfo{
						SchemaVersion: 1,
						Digest:        "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
						DiffId:        "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
						OpaqueDirs:    []string{"etc/"},
						WhiteoutFiles: []string{"etc/hostname"},
						Os: &common.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						PackageInfos: []*common.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []*common.Package{
									{
										Name:       "binary",
										Version:    "1.2.3",
										Release:    "1",
										Epoch:      2,
										Arch:       "x86_64",
										SrcName:    "src",
										SrcVersion: "1.2.3",
										SrcRelease: "1",
										SrcEpoch:   2,
										Layer: &common.Layer{
											Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
											DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
										},
									},
									{
										Name:       "vim-minimal",
										Version:    "7.4.160",
										Release:    "5.el7",
										Epoch:      2,
										Arch:       "x86_64",
										SrcName:    "vim",
										SrcVersion: "7.4.160",
										SrcRelease: "5.el7",
										SrcEpoch:   2,
										Layer: &common.Layer{
											Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
											DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
										},
									},
									{
										Name:       "node-minimal",
										Version:    "17.1.0",
										Release:    "5.el7",
										Epoch:      2,
										Arch:       "x86_64",
										SrcName:    "node",
										SrcVersion: "17.1.0",
										SrcRelease: "5.el7",
										SrcEpoch:   2,
										Layer:      nil,
									},
								},
							},
						},
						Applications: []*common.Application{
							{
								Type:     "composer",
								FilePath: "php-app/composer.lock",
								Packages: []*common.Package{
									{
										Name:    "guzzlehttp/guzzle",
										Version: "6.2.0",
									},
									{
										Name:    "guzzlehttp/promises",
										Version: "v1.3.1",
									},
								},
							},
						},
					},
				},
			},
			wantBlobs: []cachetest.WantBlob{
				{
					ID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					BlobInfo: ftypes.BlobInfo{
						SchemaVersion: 1,
						Digest:        "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
						DiffID:        "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
						OpaqueDirs:    []string{"etc/"},
						WhiteoutFiles: []string{"etc/hostname"},
						OS: ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						PackageInfos: []ftypes.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: ftypes.Packages{
									{
										Name:       "binary",
										Version:    "1.2.3",
										Release:    "1",
										Epoch:      2,
										Arch:       "x86_64",
										SrcName:    "src",
										SrcVersion: "1.2.3",
										SrcRelease: "1",
										SrcEpoch:   2,
										Layer: ftypes.Layer{
											Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
											DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
										},
									},
									{
										Name:       "vim-minimal",
										Version:    "7.4.160",
										Release:    "5.el7",
										Epoch:      2,
										Arch:       "x86_64",
										SrcName:    "vim",
										SrcVersion: "7.4.160",
										SrcRelease: "5.el7",
										SrcEpoch:   2,
										Layer: ftypes.Layer{
											Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
											DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
										},
									},
									{
										Name:       "node-minimal",
										Version:    "17.1.0",
										Release:    "5.el7",
										Epoch:      2,
										Arch:       "x86_64",
										SrcName:    "node",
										SrcVersion: "17.1.0",
										SrcRelease: "5.el7",
										SrcEpoch:   2,
										Layer:      ftypes.Layer{},
									},
								},
							},
						},
						Applications: []ftypes.Application{
							{
								Type:     "composer",
								FilePath: "php-app/composer.lock",
								Packages: ftypes.Packages{
									{
										Name:    "guzzlehttp/guzzle",
										Version: "6.2.0",
									},
									{
										Name:    "guzzlehttp/promises",
										Version: "v1.3.1",
									},
								},
							},
						},
					},
				},
			},
			want: &emptypb.Empty{},
		},
		{
			name: "sad path",
			args: args{
				in: &rpcCache.PutBlobRequest{
					BlobInfo: &rpcCache.BlobInfo{
						SchemaVersion: 1,
					},
				},
			},
			setUpCache: func(_ *testing.T) cache.Cache {
				return cachetest.NewErrorCache(cachetest.ErrorCacheOptions{
					PutBlob: true,
				})
			},
			wantErr: "unable to store layer info in cache",
		},
		{
			name: "sad path: empty layer info",
			args: args{
				in: &rpcCache.PutBlobRequest{},
			},
			wantErr: "empty layer info",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cachetest.NewCache(t, tt.setUpCache)

			s := NewCacheServer(c)
			got, err := s.PutBlob(t.Context(), tt.args.in)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr, tt.name)
				return
			}

			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got)
			cachetest.AssertBlobs(t, c, tt.wantBlobs)
		})
	}
}

func TestCacheServer_MissingBlobs(t *testing.T) {
	type args struct {
		ctx context.Context
		in  *rpcCache.MissingBlobsRequest
	}
	tests := []struct {
		name       string
		args       args
		setUpCache func(t *testing.T) cache.Cache
		want       *rpcCache.MissingBlobsResponse
		wantErr    string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcCache.MissingBlobsRequest{
					ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					BlobIds: []string{
						"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
				},
			},
			setUpCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutArtifact(t.Context(), "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a", ftypes.ArtifactInfo{
					SchemaVersion: ftypes.ArtifactJSONSchemaVersion,
				}))

				require.NoError(t, c.PutBlob(t.Context(), "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
				}))

				return c
			},
			want: &rpcCache.MissingBlobsResponse{
				MissingArtifact: false,
				MissingBlobIds:  []string{"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cachetest.NewCache(t, tt.setUpCache)

			s := NewCacheServer(c)
			got, err := s.MissingBlobs(tt.args.ctx, tt.args.in)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr, tt.name)
				return
			}
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got)
		})
	}
}
