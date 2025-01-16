package applier_test

import (
	"sort"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
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
		name                    string
		args                    args
		getLayerExpectations    []cache.LocalArtifactCacheGetBlobExpectation
		getArtifactExpectations []cache.LocalArtifactCacheGetArtifactExpectation
		want                    types.ArtifactDetail
		wantErr                 string
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
									Packages: types.Packages{
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
									Packages: types.Packages{
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
									Packages: types.Packages{
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
			getArtifactExpectations: []cache.LocalArtifactCacheGetArtifactExpectation{
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
				Packages: types.Packages{
					{
						Name:       "libc6",
						Version:    "2.24-11+deb9u4",
						SrcName:    "glibc",
						SrcVersion: "2.24-11+deb9u4",
						Identifier: types.PkgIdentifier{
							UID: "1565c6a375877d3d",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeDebian,
								Namespace: "debian",
								Name:      "libc6",
								Version:   "2.24-11+deb9u4",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "debian-9.9",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
					{
						Name:       "tzdata",
						Version:    "2019a-0+deb9u1",
						SrcName:    "tzdata",
						SrcVersion: "2019a-0+deb9u1",
						Identifier: types.PkgIdentifier{
							UID: "15974c575bfa26a7",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeDebian,
								Namespace: "debian",
								Name:      "tzdata",
								Version:   "2019a-0+deb9u1",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "debian-9.9",
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
						Type:     "composer",
						FilePath: "php-app/composer.lock",
						Packages: types.Packages{
							{
								Name:    "guzzlehttp/guzzle",
								Version: "6.2.0",
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
								Identifier: types.PkgIdentifier{
									UID: "38462330435c69bc",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "guzzlehttp",
										Name:      "guzzle",
										Version:   "6.2.0",
									},
								},
							},
							{
								Name:    "symfony/process",
								Version: "v4.2.7",
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
								Identifier: types.PkgIdentifier{
									UID: "ef7e3567678854cb",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "symfony",
										Name:      "process",
										Version:   "v4.2.7",
									},
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
									Packages: types.Packages{
										{
											Name:    "musl",
											Version: "1.1.22-r3",
										},
										{
											Name:    "busybox",
											Version: "1.30.1-r3",
										},
										{
											Name:    "openssl",
											Version: "1.1.1d-r2",
										},
										{
											Name:    "libcrypto1.1",
											Version: "1.1.1d-r2",
										},
										{
											Name:    "libssl1.1",
											Version: "1.1.1d-r2",
										},
									},
								},
							},
						},
					},
				},
			},
			getArtifactExpectations: []cache.LocalArtifactCacheGetArtifactExpectation{
				{
					Args: cache.LocalArtifactCacheGetArtifactArgs{
						ArtifactID: "sha256:3bb70bd5fb37e05b8ecaaace5d6a6b5ec7834037c07ecb5907355c23ab70352d",
					},
					Returns: cache.LocalArtifactCacheGetArtifactReturns{
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: 1,
							HistoryPackages: types.Packages{
								{
									Name:    "musl",
									Version: "1.1.23",
								},
								{
									Name:    "busybox",
									Version: "1.31",
								},
								{
									Name:    "ncurses-libs",
									Version: "6.1_p20190518-r0",
								},
								{
									Name:    "ncurses-terminfo-base",
									Version: "6.1_p20190518-r0",
								},
								{
									Name:    "ncurses",
									Version: "6.1_p20190518-r0",
								},
								{
									Name:    "ncurses-terminfo",
									Version: "6.1_p20190518-r0",
								},
								{
									Name:    "bash",
									Version: "5.0.0-r0",
								},
								{
									Name:    "readline",
									Version: "8.0.0-r0",
								},
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
				Packages: types.Packages{
					{
						Name:    "busybox",
						Version: "1.30.1-r3",
						Identifier: types.PkgIdentifier{
							UID: "3bfef897b9fcc058",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeApk,
								Namespace: "alpine",
								Name:      "busybox",
								Version:   "1.30.1-r3",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "3.10.4",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "libcrypto1.1",
						Version: "1.1.1d-r2",
						Identifier: types.PkgIdentifier{
							UID: "a4495e1af163f55a",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeApk,
								Namespace: "alpine",
								Name:      "libcrypto1.1",
								Version:   "1.1.1d-r2",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "3.10.4",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "libssl1.1",
						Version: "1.1.1d-r2",
						Identifier: types.PkgIdentifier{
							UID: "4c683a33e3b7899c",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeApk,
								Namespace: "alpine",
								Name:      "libssl1.1",
								Version:   "1.1.1d-r2",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "3.10.4",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "musl",
						Version: "1.1.22-r3",
						Identifier: types.PkgIdentifier{
							UID: "bb9bd4dfce8858bf",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeApk,
								Namespace: "alpine",
								Name:      "musl",
								Version:   "1.1.22-r3",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "3.10.4",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "openssl",
						Version: "1.1.1d-r2",
						Identifier: types.PkgIdentifier{
							UID: "3f6c865591e06595",
							//PURL: "pkg:apk/alpine/openssl@1.1.1d-r2?distro=3.10.4",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeApk,
								Namespace: "alpine",
								Name:      "openssl",
								Version:   "1.1.1d-r2",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "3.10.4",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
				},
				ImageConfig: types.ImageConfigDetail{
					Packages: types.Packages{
						{
							Name:    "musl",
							Version: "1.1.23",
						},
						{
							Name:    "busybox",
							Version: "1.31",
						},
						{
							Name:    "ncurses-libs",
							Version: "6.1_p20190518-r0",
						},
						{
							Name:    "ncurses-terminfo-base",
							Version: "6.1_p20190518-r0",
						},
						{
							Name:    "ncurses",
							Version: "6.1_p20190518-r0",
						},
						{
							Name:    "ncurses-terminfo",
							Version: "6.1_p20190518-r0",
						},
						{
							Name:    "bash",
							Version: "5.0.0-r0",
						},
						{
							Name:    "readline",
							Version: "8.0.0-r0",
						},
					},
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
			getArtifactExpectations: []cache.LocalArtifactCacheGetArtifactExpectation{
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
									Packages: types.Packages{
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
									Packages: types.Packages{
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
									Packages: types.Packages{
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
				Packages: types.Packages{
					{
						Name:       "libc6",
						Version:    "2.24-11+deb9u4",
						SrcName:    "glibc",
						SrcVersion: "2.24-11+deb9u4",
						Layer: types.Layer{
							Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
						Identifier: types.PkgIdentifier{
							UID: "1565c6a375877d3d",
						},
					},
					{
						Name:       "tzdata",
						Version:    "2019a-0+deb9u1",
						SrcName:    "tzdata",
						SrcVersion: "2019a-0+deb9u1",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
						Identifier: types.PkgIdentifier{
							UID: "15974c575bfa26a7",
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "composer",
						FilePath: "php-app/composer.lock",
						Packages: types.Packages{
							{
								Name:    "guzzlehttp/guzzle",
								Version: "6.2.0",
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
								Identifier: types.PkgIdentifier{
									UID: "38462330435c69bc",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "guzzlehttp",
										Name:      "guzzle",
										Version:   "6.2.0",
									},
								},
							},
							{
								Name:    "symfony/process",
								Version: "v4.2.7",
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
								Identifier: types.PkgIdentifier{
									UID: "ef7e3567678854cb",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "symfony",
										Name:      "process",
										Version:   "v4.2.7",
									},
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
				imageID: "sha256:4791503518dff090d6a82f7a5c1fd71c41146920e2562fb64308e17ab6834b7e",
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
			getArtifactExpectations: []cache.LocalArtifactCacheGetArtifactExpectation{
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
			getArtifactExpectations: []cache.LocalArtifactCacheGetArtifactExpectation{
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
									Packages: types.Packages{
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
									Packages: types.Packages{
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
				Packages: types.Packages{
					{
						Name:       "tzdata",
						Version:    "2019a-0+deb9u1",
						SrcName:    "tzdata",
						SrcVersion: "2019a-0+deb9u1",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
						Identifier: types.PkgIdentifier{
							UID: "15974c575bfa26a7",
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "composer",
						FilePath: "php-app/composer.lock",
						Packages: types.Packages{
							{
								Name:    "guzzlehttp/guzzle",
								Version: "6.2.0",
								Layer: types.Layer{
									Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
									DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
								},
								Identifier: types.PkgIdentifier{
									UID: "38462330435c69bc",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "guzzlehttp",
										Name:      "guzzle",
										Version:   "6.2.0",
									},
								},
							},
							{
								Name:    "symfony/process",
								Version: "v4.2.7",
								Layer: types.Layer{
									Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
									DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
								},
								Identifier: types.PkgIdentifier{
									UID: "ef7e3567678854cb",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "symfony",
										Name:      "process",
										Version:   "v4.2.7",
									},
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
		{
			name: "SUSE images - legacy OS name with backward compatibility",
			args: args{
				imageID: "sha256:fb44d01953611ba18d43d88e158c25579d18eff42db671182245010620a283f3",
				layerIDs: []string{
					"sha256:2615f175cf3da67c48c6542914744943ee5e9c253547b03e3cfe8aae605c3199",
				},
			},
			getLayerExpectations: []cache.LocalArtifactCacheGetBlobExpectation{
				{
					Args: cache.LocalArtifactCacheGetBlobArgs{
						BlobID: "sha256:2615f175cf3da67c48c6542914744943ee5e9c253547b03e3cfe8aae605c3199",
					},
					Returns: cache.LocalArtifactCacheGetBlobReturns{
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "sha256:fb44d01953611ba18d43d88e158c25579d18eff42db671182245010620a283f3",
							DiffID:        "sha256:d555e1b0b42f21a1cf198e52bcb12fe66aa015348e4390d2d5acddd327d79073",
							OS: types.OS{
								Family: "suse linux enterprise server",
								Name:   "15.4",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "usr/lib/sysimage/rpm/Packages.db",
									Packages: types.Packages{
										{
											Name:       "curl",
											Version:    "7.79.1",
											SrcName:    "curl",
											SrcVersion: "7.79.1",
										},
									},
								},
							},
						},
					},
				},
			},
			getArtifactExpectations: []cache.LocalArtifactCacheGetArtifactExpectation{
				{
					Args: cache.LocalArtifactCacheGetArtifactArgs{
						ArtifactID: "sha256:fb44d01953611ba18d43d88e158c25579d18eff42db671182245010620a283f3",
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
					Family: "sles",
					Name:   "15.4",
				},
				Packages: types.Packages{
					{
						Name:       "curl",
						Version:    "7.79.1",
						SrcName:    "curl",
						SrcVersion: "7.79.1",
						Identifier: types.PkgIdentifier{
							UID: "1e9b3d3a73785651",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeRPM,
								Namespace: "suse",
								Name:      "curl",
								Version:   "7.79.1",
								Qualifiers: packageurl.Qualifiers{
									{
										Key:   "distro",
										Value: "sles-15.4",
									},
								},
							},
						},
						Layer: types.Layer{
							Digest: "sha256:fb44d01953611ba18d43d88e158c25579d18eff42db671182245010620a283f3",
							DiffID: "sha256:d555e1b0b42f21a1cf198e52bcb12fe66aa015348e4390d2d5acddd327d79073",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockLocalArtifactCache)
			c.ApplyGetBlobExpectations(tt.getLayerExpectations)
			c.ApplyGetArtifactExpectations(tt.getArtifactExpectations)

			a := applier.NewApplier(c)

			got, err := a.ApplyLayers(tt.args.imageID, tt.args.layerIDs)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}

			sort.Sort(got.Packages)
			for _, app := range got.Applications {
				sort.Sort(app.Packages)
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
