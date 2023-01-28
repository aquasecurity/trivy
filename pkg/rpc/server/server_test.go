package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
	"github.com/aquasecurity/trivy/rpc/common"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

type mockCache struct {
	cache.MockArtifactCache
	cache.MockLocalArtifactCache
}

func TestScanServer_Scan(t *testing.T) {
	type args struct {
		in *rpcScanner.ScanRequest
	}
	tests := []struct {
		name            string
		args            args
		scanExpectation scanner.DriverScanExpectation
		want            *rpcScanner.ScanResponse
		wantErr         string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcScanner.ScanRequest{
					Target:     "alpine:3.11",
					ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					BlobIds:    []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					Options:    &rpcScanner.ScanOptions{},
				},
			},
			scanExpectation: scanner.DriverScanExpectation{
				Args: scanner.DriverScanArgs{
					CtxAnything:     true,
					Target:          "alpine:3.11",
					ImageID:         "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIDs:        []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					OptionsAnything: true,
				},
				Returns: scanner.DriverScanReturns{
					Results: types.Results{
						{
							Target: "alpine:3.11 (alpine 3.11)",
							Vulnerabilities: []types.DetectedVulnerability{
								{
									VulnerabilityID:  "CVE-2019-0001",
									PkgName:          "musl",
									InstalledVersion: "1.2.3",
									FixedVersion:     "1.2.4",
									SeveritySource:   "nvd",
									Vulnerability: dbTypes.Vulnerability{
										Title:       "dos",
										Description: "dos vulnerability",
										Severity:    "MEDIUM",
										VendorSeverity: map[dbTypes.SourceID]dbTypes.Severity{
											vulnerability.NVD: dbTypes.SeverityMedium,
										},
										References:       []string{"http://example.com"},
										LastModifiedDate: utils.MustTimeParse("2020-01-01T01:01:00Z"),
										PublishedDate:    utils.MustTimeParse("2001-01-01T01:01:00Z"),
									},
									PrimaryURL: "https://avd.aquasec.com/nvd/cve-2019-0001",
									DataSource: &dbTypes.DataSource{
										Name: "DOS vulnerabilities",
										URL:  "https://vuld-db-example.com/",
									},
								},
							},
							Type: "alpine",
						},
					},
					OsFound: ftypes.OS{
						Family: "alpine",
						Name:   "3.11",
						Eosl:   true,
					},
				},
			},
			want: &rpcScanner.ScanResponse{
				Os: &common.OS{
					Family: "alpine",
					Name:   "3.11",
					Eosl:   true,
				},
				Results: []*rpcScanner.Result{
					{
						Target: "alpine:3.11 (alpine 3.11)",
						Vulnerabilities: []*common.Vulnerability{
							{
								VulnerabilityId:  "CVE-2019-0001",
								PkgName:          "musl",
								InstalledVersion: "1.2.3",
								FixedVersion:     "1.2.4",
								Severity:         common.Severity_MEDIUM,
								SeveritySource:   "nvd",
								Layer:            &common.Layer{},
								Cvss:             map[string]*common.CVSS{},
								VendorSeverity: map[string]common.Severity{
									string(vulnerability.NVD): common.Severity_MEDIUM,
								},
								PrimaryUrl:  "https://avd.aquasec.com/nvd/cve-2019-0001",
								Title:       "dos",
								Description: "dos vulnerability",
								References:  []string{"http://example.com"},
								LastModifiedDate: &timestamp.Timestamp{
									Seconds: 1577840460,
								},
								PublishedDate: &timestamp.Timestamp{
									Seconds: 978310860,
								},
								DataSource: &common.DataSource{
									Name: "DOS vulnerabilities",
									Url:  "https://vuld-db-example.com/",
								},
							},
						},
						Type: "alpine",
					},
				},
			},
		},
		{
			name: "sad path: Scan returns an error",
			args: args{
				in: &rpcScanner.ScanRequest{
					Target:     "alpine:3.11",
					ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					BlobIds:    []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					Options:    &rpcScanner.ScanOptions{},
				},
			},
			scanExpectation: scanner.DriverScanExpectation{
				Args: scanner.DriverScanArgs{
					CtxAnything:     true,
					Target:          "alpine:3.11",
					ImageID:         "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIDs:        []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					OptionsAnything: true,
				},
				Returns: scanner.DriverScanReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed scan, alpine:3.11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDriver := new(scanner.MockDriver)
			mockDriver.ApplyScanExpectation(tt.scanExpectation)

			s := NewScanServer(mockDriver)
			got, err := s.Scan(context.Background(), tt.args.in)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}
			assert.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCacheServer_PutArtifact(t *testing.T) {
	type args struct {
		in *rpcCache.PutArtifactRequest
	}
	tests := []struct {
		name     string
		args     args
		putImage cache.ArtifactCachePutArtifactExpectation
		want     *google_protobuf.Empty
		wantErr  string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcCache.PutArtifactRequest{
					ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ArtifactInfo: &rpcCache.ArtifactInfo{
						SchemaVersion: 1,
						Architecture:  "amd64",
						Created: func() *timestamp.Timestamp {
							d := time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC)
							t, _ := ptypes.TimestampProto(d)
							return t
						}(),
						DockerVersion: "18.09",
						Os:            "linux",
					},
				},
			},
			putImage: cache.ArtifactCachePutArtifactExpectation{
				Args: cache.ArtifactCachePutArtifactArgs{
					ArtifactID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ArtifactInfo: ftypes.ArtifactInfo{
						SchemaVersion: 1,
						Architecture:  "amd64",
						Created:       time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC),
						DockerVersion: "18.09",
						OS:            "linux",
					},
				},
			},
			want: &google_protobuf.Empty{},
		},
		{
			name: "sad path",
			args: args{
				in: &rpcCache.PutArtifactRequest{
					ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ArtifactInfo: &rpcCache.ArtifactInfo{
						SchemaVersion: 1,
						Created: func() *timestamp.Timestamp {
							d := time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC)
							t, _ := ptypes.TimestampProto(d)
							return t
						}(),
					},
				},
			},
			putImage: cache.ArtifactCachePutArtifactExpectation{
				Args: cache.ArtifactCachePutArtifactArgs{
					ArtifactID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ArtifactInfo: ftypes.ArtifactInfo{
						SchemaVersion: 1,
						Created:       time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC),
					},
				},
				Returns: cache.ArtifactCachePutArtifactReturns{
					Err: xerrors.New("error"),
				},
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
			mockCache := new(mockCache)
			mockCache.ApplyPutArtifactExpectation(tt.putImage)

			s := NewCacheServer(mockCache)
			got, err := s.PutArtifact(context.Background(), tt.args.in)

			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCacheServer_PutBlob(t *testing.T) {
	type args struct {
		in *rpcCache.PutBlobRequest
	}
	tests := []struct {
		name     string
		args     args
		putLayer cache.ArtifactCachePutBlobExpectation
		want     *google_protobuf.Empty
		wantErr  string
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
								Libraries: []*common.Package{
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
						OpaqueDirs:    []string{"etc/"},
						WhiteoutFiles: []string{"etc/hostname"},
					},
				},
			},
			putLayer: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					BlobInfo: ftypes.BlobInfo{
						SchemaVersion: 1,
						Digest:        "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
						DiffID:        "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
						OS: ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						PackageInfos: []ftypes.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []ftypes.Package{
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
								Libraries: []ftypes.Package{
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
						OpaqueDirs:    []string{"etc/"},
						WhiteoutFiles: []string{"etc/hostname"},
					},
				},
			},
			want: &google_protobuf.Empty{},
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
			putLayer: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything:   true,
					BlobInfoAnything: true,
				},
				Returns: cache.ArtifactCachePutBlobReturns{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "unable to store layer info in cache",
		},
		{
			name: "sad path: empty layer info",
			args: args{
				in: &rpcCache.PutBlobRequest{},
			},
			putLayer: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything:   true,
					BlobInfoAnything: true,
				},
				Returns: cache.ArtifactCachePutBlobReturns{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "empty layer info",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(mockCache)
			mockCache.ApplyPutBlobExpectation(tt.putLayer)

			s := NewCacheServer(mockCache)
			got, err := s.PutBlob(context.Background(), tt.args.in)

			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCacheServer_MissingBlobs(t *testing.T) {
	type args struct {
		ctx context.Context
		in  *rpcCache.MissingBlobsRequest
	}
	tests := []struct {
		name                                     string
		args                                     args
		getArtifactCacheMissingBlobsExpectations []cache.ArtifactCacheMissingBlobsExpectation
		want                                     *rpcCache.MissingBlobsResponse
		wantErr                                  string
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
			getArtifactCacheMissingBlobsExpectations: []cache.ArtifactCacheMissingBlobsExpectation{
				{
					Args: cache.ArtifactCacheMissingBlobsArgs{ArtifactID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
						BlobIDs: []string{"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02", "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5"}},
					Returns: cache.ArtifactCacheMissingBlobsReturns{
						MissingArtifact: false, MissingBlobIDs: []string{"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5"}, Err: nil},
				},
			},
			want: &rpcCache.MissingBlobsResponse{
				MissingArtifact: false,
				MissingBlobIds:  []string{"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(mockCache)
			mockCache.ApplyMissingBlobsExpectations(tt.getArtifactCacheMissingBlobsExpectations)

			s := NewCacheServer(mockCache)
			got, err := s.MissingBlobs(tt.args.ctx, tt.args.in)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got)
			mockCache.MockArtifactCache.AssertExpectations(t)
		})
	}
}
