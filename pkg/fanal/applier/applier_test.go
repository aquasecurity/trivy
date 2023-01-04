package applier_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type dummyData struct {
	data string
}

func TestApplier_ApplyLayers(t *testing.T) {
	type args struct {
		imageID  string
		layerIDs []string
	}
	tests := []struct {
		name                 string
		args                 args
		getLayerExpectations []cache.LocalArtifactCacheGetBlobExpectation
		getImageExpectations []cache.LocalArtifactCacheGetArtifactExpectation
		want                 types.ArtifactDetail
		wantErr              string
	}{
		{
			name: "happy path",
			args: args{
				imageID: "sha256:4791503518dff090d6a82f7a5c1fd71c41146920e2562fb64308e17ab6834b7e",
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				},
			},
			getLayerExpectations: []cache.LocalArtifactCacheGetBlobExpectation{
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							OS: types.OS{
								Family: "debian",
								Name:   "9.9",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Packages: []types.Package{
										{
											Name:       "tzdata",
											Version:    "2019a-0+deb9u1",
											SrcName:    "tzdata",
											SrcVersion: "2019a-0+deb9u1",
										},
									},
								},
							},
						},
					},
				},
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/libc6",
									Packages: []types.Package{
										{
											Name:       "libc6",
											Version:    "2.24-11+deb9u4",
											SrcName:    "glibc",
											SrcVersion: "2.24-11+deb9u4",
										},
									},
								},
							},
							Applications:  nil,
							OpaqueDirs:    nil,
							WhiteoutFiles: nil,
						},
					},
				},
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							Applications: []types.Application{
								{
									Type:     "composer",
									FilePath: "php-app/composer.lock",
									Libraries: []types.Package{
										{
											Name:    "guzzlehttp/guzzle",
											Version: "6.2.0",
										},
										{
											Name:    "symfony/process",
											Version: "v4.2.7",
										},
									},
								},
							},
						},
					},
				},
			},
			getImageExpectations: []cache.LocalArtifactCacheGetArtifactExpectation{
				{
					Args: cache.LocalArtifactCacheGetArtifactArgs{
						ArtifactID: "sha256:4791503518dff090d6a82f7a5c1fd71c41146920e2562fb64308e17ab6834b7e",
					},
					Returns: cache.LocalArtifactCacheGetArtifactReturns{
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: 1,
						},
					},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family: "debian",
					Name:   "9.9",
				},
				Packages: []types.Package{
					{
						Name: "libc6", Version: "2.24-11+deb9u4", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4",
						Layer: types.Layer{
							Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
					{
						Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "composer",
						FilePath: "php-app/composer.lock",
						Libraries: []types.Package{
							{
								Name:    "guzzlehttp/guzzle",
								Version: "6.2.0",
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
							},
							{
								Name:    "symfony/process",
								Version: "v4.2.7",
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with history packages",
			args: args{
				imageID: "sha256:3bb70bd5fb37e05b8ecaaace5d6a6b5ec7834037c07ecb5907355c23ab70352d",
				layerIDs: []string{
					"sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
				},
			},
			getLayerExpectations: []cache.LocalArtifactCacheGetBlobExpectation{
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID:        "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
							OS: types.OS{
								Family: "alpine",
								Name:   "3.10.4",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "lib/apk/db/installed",
									Packages: []types.Package{
										{Name: "musl", Version: "1.1.22-r3"},
										{Name: "busybox", Version: "1.30.1-r3"},
										{Name: "openssl", Version: "1.1.1d-r2"},
										{Name: "libcrypto1.1", Version: "1.1.1d-r2"},
										{Name: "libssl1.1", Version: "1.1.1d-r2"},
									},
								},
							},
						},
					},
				},
			},
			getImageExpectations: []cache.LocalArtifactCacheGetArtifactExpectation{
				{
					Args: cache.LocalArtifactCacheGetArtifactArgs{
						ArtifactID: "sha256:3bb70bd5fb37e05b8ecaaace5d6a6b5ec7834037c07ecb5907355c23ab70352d",
					},
					Returns: cache.LocalArtifactCacheGetArtifactReturns{
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: 1,
							HistoryPackages: []types.Package{
								{Name: "musl", Version: "1.1.23"},
								{Name: "busybox", Version: "1.31"},
								{Name: "ncurses-libs", Version: "6.1_p20190518-r0"},
								{Name: "ncurses-terminfo-base", Version: "6.1_p20190518-r0"},
								{Name: "ncurses", Version: "6.1_p20190518-r0"},
								{Name: "ncurses-terminfo", Version: "6.1_p20190518-r0"},
								{Name: "bash", Version: "5.0.0-r0"},
								{Name: "readline", Version: "8.0.0-r0"},
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family: "alpine",
					Name:   "3.10.4",
				},
				Packages: []types.Package{
					{
						Name:    "busybox",
						Version: "1.30.1-r3",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "libcrypto1.1",
						Version: "1.1.1d-r2",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "libssl1.1",
						Version: "1.1.1d-r2",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "musl",
						Version: "1.1.22-r3",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "openssl",
						Version: "1.1.1d-r2",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
				},
				HistoryPackages: []types.Package{
					{Name: "musl", Version: "1.1.23"},
					{Name: "busybox", Version: "1.31"},
					{Name: "ncurses-libs", Version: "6.1_p20190518-r0"},
					{Name: "ncurses-terminfo-base", Version: "6.1_p20190518-r0"},
					{Name: "ncurses", Version: "6.1_p20190518-r0"},
					{Name: "ncurses-terminfo", Version: "6.1_p20190518-r0"},
					{Name: "bash", Version: "5.0.0-r0"},
					{Name: "readline", Version: "8.0.0-r0"},
				},
			},
		},
		{
			name: "sad path GetBlob returns an error",
			args: args{
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
			getLayerExpectations: []cache.LocalArtifactCacheGetBlobExpectation{
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{BlobInfo: types.BlobInfo{}},
				},
			},
			wantErr: "layer cache missing",
		},
		{
			name: "sad path GetBlob returns empty layer info",
			args: args{
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
			getLayerExpectations: []cache.LocalArtifactCacheGetBlobExpectation{
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{BlobInfo: types.BlobInfo{}},
				},
			},
			wantErr: "layer cache missing",
		},
		{
			name: "happy path with some packages but unknown OS",
			args: args{
				imageID: "sha256:4791503518dff090d6a82f7a5c1fd71c41146920e2562fb64308e17ab6834b7e",
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				},
			},
			getLayerExpectations: []cache.LocalArtifactCacheGetBlobExpectation{
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Packages: []types.Package{
										{
											Name:       "tzdata",
											Version:    "2019a-0+deb9u1",
											SrcName:    "tzdata",
											SrcVersion: "2019a-0+deb9u1",
										},
									},
								},
							},
						},
					},
				},
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/libc6",
									Packages: []types.Package{
										{
											Name:       "libc6",
											Version:    "2.24-11+deb9u4",
											SrcName:    "glibc",
											SrcVersion: "2.24-11+deb9u4",
										},
									},
								},
							},
							Applications:  nil,
							OpaqueDirs:    nil,
							WhiteoutFiles: nil,
						},
					},
				},
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							Applications: []types.Application{
								{
									Type:     "composer",
									FilePath: "php-app/composer.lock",
									Libraries: []types.Package{
										{
											Name:    "guzzlehttp/guzzle",
											Version: "6.2.0",
										},
										{
											Name:    "symfony/process",
											Version: "v4.2.7",
										},
									},
								},
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				Packages: []types.Package{
					{
						Name: "libc6", Version: "2.24-11+deb9u4", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4",
						Layer: types.Layer{
							Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
					{
						Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "composer",
						FilePath: "php-app/composer.lock",
						Libraries: []types.Package{
							{
								Name:    "guzzlehttp/guzzle",
								Version: "6.2.0",
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
							},
							{
								Name:    "symfony/process",
								Version: "v4.2.7",
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
							},
						},
					},
				},
			},
			wantErr: "unknown OS",
		},
		{
			name: "sad path no package detected",
			args: args{
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
			getLayerExpectations: []cache.LocalArtifactCacheGetBlobExpectation{
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							OS: types.OS{
								Family: "debian",
								Name:   "9.9",
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				OS: types.OS{
					Family: "debian",
					Name:   "9.9",
				},
			},
			wantErr: "no packages detected",
		},
		{
			name: "happy path with custom resources",
			args: args{
				imageID: "sha256:4791503518dff090d6a82f7a5c1fd71c41146920e2562fb64308e17ab6834b7e",
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				},
			},
			getLayerExpectations: []cache.LocalArtifactCacheGetBlobExpectation{
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Packages: []types.Package{
										{
											Name:       "tzdata",
											Version:    "2019a-0+deb9u1",
											SrcName:    "tzdata",
											SrcVersion: "2019a-0+deb9u1",
										},
									},
								},
							},
							CustomResources: []types.CustomResource{
								{
									Type:     "type-A",
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Data: dummyData{
										data: "Common Package type-A var/lib/dpkg/status.d/tzdata",
									},
								},
								{
									Type:     "type-B",
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Data: dummyData{
										data: "Common Package type-B, overidden in next layer",
									},
								},
							},
						},
					},
				},
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
							Applications: []types.Application{
								{
									Type:     "composer",
									FilePath: "php-app/composer.lock",
									Libraries: []types.Package{
										{
											Name:    "guzzlehttp/guzzle",
											Version: "6.2.0",
										},
										{
											Name:    "symfony/process",
											Version: "v4.2.7",
										},
									},
								},
							},
							CustomResources: []types.CustomResource{
								{
									Type:     "type-A",
									FilePath: "php-app/composer.lock",
									Data: dummyData{
										data: "Common Application type-A php-app/composer.lock",
									},
								},
								{
									Type:     "type-B",
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Data: dummyData{
										data: "Type B application which replaces earlier detected resource",
									},
								},
							},
						},
					},
				},
			},
			want: types.ArtifactDetail{
				Packages: []types.Package{
					{
						Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "composer",
						FilePath: "php-app/composer.lock",
						Libraries: []types.Package{
							{
								Name:    "guzzlehttp/guzzle",
								Version: "6.2.0",
								Layer: types.Layer{
									Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
									DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
								},
							},
							{
								Name:    "symfony/process",
								Version: "v4.2.7",
								Layer: types.Layer{
									Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
									DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
								},
							},
						},
					},
				},
				CustomResources: []types.CustomResource{
					{
						Type:     "type-A",
						FilePath: "php-app/composer.lock",
						Layer: types.Layer{
							Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
						Data: dummyData{
							data: "Common Application type-A php-app/composer.lock",
						},
					},
					{
						Type:     "type-A",
						FilePath: "var/lib/dpkg/status.d/tzdata",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
						Data: dummyData{
							data: "Common Package type-A var/lib/dpkg/status.d/tzdata",
						},
					},
					{
						Type:     "type-B",
						FilePath: "var/lib/dpkg/status.d/tzdata",
						Layer: types.Layer{
							Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
						Data: dummyData{
							data: "Type B application which replaces earlier detected resource",
						},
					},
				},
			},
			wantErr: "unknown OS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockLocalArtifactCache)
			c.ApplyGetBlobExpectations(tt.getLayerExpectations)
			c.ApplyGetArtifactExpectations(tt.getImageExpectations)

			a := applier.NewApplier(c)

			got, err := a.ApplyLayers(tt.args.imageID, tt.args.layerIDs)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}

			sort.Sort(got.Packages)
			for _, app := range got.Applications {
				sort.Slice(app.Libraries, func(i, j int) bool {
					return app.Libraries[i].Name < app.Libraries[j].Name
				})
			}

			sort.Slice(got.CustomResources, func(i, j int) bool {
				if got.CustomResources[i].FilePath == got.CustomResources[j].FilePath {
					return got.CustomResources[i].Type < got.CustomResources[j].Type
				}
				return got.CustomResources[i].FilePath < got.CustomResources[j].FilePath
			})

			assert.Equal(t, tt.want, got)
			c.AssertExpectations(t)
		})
	}
}
