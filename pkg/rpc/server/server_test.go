package server

import (
	"context"
	"errors"
	"testing"
	"time"

	deptypes "github.com/aquasecurity/go-dep-parser/pkg/types"

	"github.com/golang/protobuf/ptypes/timestamp"

	"github.com/golang/protobuf/ptypes"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
	"github.com/aquasecurity/trivy/rpc/common"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

type mockCache struct {
	cache.MockImageCache
	cache.MockLocalImageCache
}

func TestScanServer_Scan(t *testing.T) {
	type args struct {
		in *rpcScanner.ScanRequest
	}
	tests := []struct {
		name                string
		args                args
		scanExpectation     scanner.ScanExpectation
		fillInfoExpectation vulnerability.FillInfoExpectation
		want                *rpcScanner.ScanResponse
		wantErr             string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcScanner.ScanRequest{
					Target:   "alpine:3.11",
					ImageId:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIds: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					Options:  &rpcScanner.ScanOptions{},
				},
			},
			scanExpectation: scanner.ScanExpectation{
				Args: scanner.ScanArgs{
					Target:   "alpine:3.11",
					ImageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: scanner.ScanReturns{
					Results: report.Results{
						{
							Target: "alpine:3.11 (alpine 3.11)",
							Vulnerabilities: []types.DetectedVulnerability{
								{
									VulnerabilityID:  "CVE-2019-0001",
									PkgName:          "musl",
									InstalledVersion: "1.2.3",
									FixedVersion:     "1.2.4",
									Vulnerability:    dbTypes.Vulnerability{},
								},
							},
						},
					},
					OsFound: &ftypes.OS{
						Family: "alpine",
						Name:   "3.11",
					},
				},
			},
			fillInfoExpectation: vulnerability.FillInfoExpectation{
				Args: vulnerability.FillInfoArgs{
					Vulns: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability:    dbTypes.Vulnerability{},
						},
					},
					Light: false,
				},
			},
			want: &rpcScanner.ScanResponse{
				Os: &common.OS{
					Family: "alpine",
					Name:   "3.11",
				},
				Eosl: false,
				Results: []*rpcScanner.Result{
					{
						Target: "alpine:3.11 (alpine 3.11)",
						Vulnerabilities: []*common.Vulnerability{
							{
								VulnerabilityId:  "CVE-2019-0001",
								PkgName:          "musl",
								InstalledVersion: "1.2.3",
								FixedVersion:     "1.2.4",
							},
						},
					},
				},
			},
		},
		{
			name: "sad path: Scan returns an error",
			args: args{
				in: &rpcScanner.ScanRequest{
					Target:   "alpine:3.11",
					ImageId:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIds: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					Options:  &rpcScanner.ScanOptions{},
				},
			},
			scanExpectation: scanner.ScanExpectation{
				Args: scanner.ScanArgs{
					Target:   "alpine:3.11",
					ImageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: scanner.ScanReturns{
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

			mockVulnClient := new(vulnerability.MockOperation)
			mockVulnClient.ApplyFillInfoExpectation(tt.fillInfoExpectation)

			s := NewScanServer(mockDriver, mockVulnClient)
			got, err := s.Scan(context.Background(), tt.args.in)
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

func TestCacheServer_PutImage(t *testing.T) {
	type args struct {
		in *rpcCache.PutImageRequest
	}
	tests := []struct {
		name     string
		args     args
		putImage cache.ImageCachePutImageExpectation
		want     *google_protobuf.Empty
		wantErr  string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcCache.PutImageRequest{
					ImageId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ImageInfo: &rpcCache.ImageInfo{
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
			putImage: cache.ImageCachePutImageExpectation{
				Args: cache.ImageCachePutImageArgs{
					ImageID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ImageInfo: ftypes.ImageInfo{
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
				in: &rpcCache.PutImageRequest{
					ImageId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ImageInfo: &rpcCache.ImageInfo{
						SchemaVersion: 1,
						Created: func() *timestamp.Timestamp {
							d := time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC)
							t, _ := ptypes.TimestampProto(d)
							return t
						}(),
					},
				},
			},
			putImage: cache.ImageCachePutImageExpectation{
				Args: cache.ImageCachePutImageArgs{
					ImageID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					ImageInfo: ftypes.ImageInfo{
						SchemaVersion: 1,
						Created:       time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC),
					},
				},
				Returns: cache.ImageCachePutImageReturns{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "unable to store image info in cache",
		},
		{
			name: "sad path: empty image info",
			args: args{
				in: &rpcCache.PutImageRequest{},
			},
			wantErr: "empty image info",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(mockCache)
			mockCache.ApplyPutImageExpectation(tt.putImage)

			s := NewCacheServer(mockCache)
			got, err := s.PutImage(context.Background(), tt.args.in)

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

func TestCacheServer_PutLayer(t *testing.T) {
	type args struct {
		in *rpcCache.PutLayerRequest
	}
	tests := []struct {
		name     string
		args     args
		putLayer cache.ImageCachePutLayerExpectation
		want     *google_protobuf.Empty
		wantErr  string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcCache.PutLayerRequest{
					LayerId:             "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
					DecompressedLayerId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					LayerInfo: &rpcCache.LayerInfo{
						SchemaVersion: 1,
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
									},
								},
							},
						},
						Applications: []*common.Application{
							{
								Type:     "composer",
								FilePath: "php-app/composer.lock",
								Libraries: []*common.Library{
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
			putLayer: cache.ImageCachePutLayerExpectation{
				Args: cache.ImageCachePutLayerArgs{
					LayerID:             "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
					DecompressedLayerID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					LayerInfo: ftypes.LayerInfo{
						SchemaVersion: 1,
						OS: &ftypes.OS{
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
									},
								},
							},
						},
						Applications: []ftypes.Application{
							{
								Type:     "composer",
								FilePath: "php-app/composer.lock",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: deptypes.Library{
											Name:    "guzzlehttp/guzzle",
											Version: "6.2.0",
										},
									},
									{
										Library: deptypes.Library{
											Name:    "guzzlehttp/promises",
											Version: "v1.3.1",
										},
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
				in: &rpcCache.PutLayerRequest{
					LayerInfo: &rpcCache.LayerInfo{
						SchemaVersion: 1,
					},
				},
			},
			putLayer: cache.ImageCachePutLayerExpectation{
				Args: cache.ImageCachePutLayerArgs{
					LayerIDAnything:             true,
					DecompressedLayerIDAnything: true,
					LayerInfoAnything:           true,
				},
				Returns: cache.ImageCachePutLayerReturns{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "unable to store layer info in cache",
		},
		{
			name: "sad path: empty layer info",
			args: args{
				in: &rpcCache.PutLayerRequest{},
			},
			putLayer: cache.ImageCachePutLayerExpectation{
				Args: cache.ImageCachePutLayerArgs{
					LayerIDAnything:             true,
					DecompressedLayerIDAnything: true,
					LayerInfoAnything:           true,
				},
				Returns: cache.ImageCachePutLayerReturns{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "empty layer info",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(mockCache)
			mockCache.ApplyPutLayerExpectation(tt.putLayer)

			s := NewCacheServer(mockCache)
			got, err := s.PutLayer(context.Background(), tt.args.in)

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

func TestCacheServer_MissingLayers(t *testing.T) {
	type args struct {
		ctx context.Context
		in  *rpcCache.MissingLayersRequest
	}
	tests := []struct {
		name                 string
		args                 args
		getLayerExpectations []cache.LocalImageCacheGetLayerExpectation
		getImageExpectations []cache.LocalImageCacheGetImageExpectation
		want                 *rpcCache.MissingLayersResponse
		wantErr              string
	}{
		{
			name: "happy path",
			args: args{
				in: &rpcCache.MissingLayersRequest{
					ImageId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIds: []string{
						"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
				},
			},
			getLayerExpectations: []cache.LocalImageCacheGetLayerExpectation{
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: ftypes.LayerInfo{},
					},
				},
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: ftypes.LayerInfo{
							SchemaVersion: 1,
						},
					},
				},
			},
			getImageExpectations: []cache.LocalImageCacheGetImageExpectation{
				{
					Args: cache.LocalImageCacheGetImageArgs{
						ImageID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					},
					Returns: cache.LocalImageCacheGetImageReturns{
						ImageInfo: ftypes.ImageInfo{
							SchemaVersion: 1,
						},
					},
				},
			},
			want: &rpcCache.MissingLayersResponse{
				MissingImage:    false,
				MissingLayerIds: []string{"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02"},
			},
		},
		{
			name: "schema version doesn't match",
			args: args{
				in: &rpcCache.MissingLayersRequest{
					ImageId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIds: []string{
						"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
				},
			},
			getLayerExpectations: []cache.LocalImageCacheGetLayerExpectation{
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: ftypes.LayerInfo{
							SchemaVersion: 0,
						},
					},
				},
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: ftypes.LayerInfo{
							SchemaVersion: -1,
						},
					},
				},
			},
			getImageExpectations: []cache.LocalImageCacheGetImageExpectation{
				{
					Args: cache.LocalImageCacheGetImageArgs{
						ImageID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					},
					Returns: cache.LocalImageCacheGetImageReturns{
						ImageInfo: ftypes.ImageInfo{},
					},
				},
			},
			want: &rpcCache.MissingLayersResponse{
				MissingImage: true,
				MissingLayerIds: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(mockCache)
			mockCache.ApplyGetLayerExpectations(tt.getLayerExpectations)
			mockCache.ApplyGetImageExpectations(tt.getImageExpectations)

			s := NewCacheServer(mockCache)
			got, err := s.MissingLayers(tt.args.ctx, tt.args.in)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got)
			mockCache.MockLocalImageCache.AssertExpectations(t)
		})
	}
}
