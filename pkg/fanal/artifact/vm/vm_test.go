package vm_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	ebsfile "github.com/masahiro331/go-ebs-file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/misconf"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/rpm"
)

const (
	ebsPrefix  = string(vm.TypeEBS) + ":"
	filePrefix = string(vm.TypeFile) + ":"
)

func TestNewArtifact(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "happy path for file",
			target:  "testdata/rawdata.img",
			wantErr: assert.NoError,
		},
		{
			name:    "happy path for EBS",
			target:  "ebs:ebs-012345",
			wantErr: assert.NoError,
		},
		{
			name:   "sad path unsupported vm format",
			target: "testdata/monolithicSparse.vmdk",
			wantErr: func(t assert.TestingT, err error, args ...interface{}) bool {
				return assert.ErrorContains(t, err, "unsupported type error")
			},
		},
		{
			name:   "sad path file not found",
			target: "testdata/no-file",
			wantErr: func(t assert.TestingT, err error, args ...interface{}) bool {
				return assert.ErrorContains(t, err, "file open error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vm.NewArtifact(tt.target, nil, artifact.Option{})
			tt.wantErr(t, err, fmt.Sprintf("NewArtifact(%v, nil, nil)", tt.target))
		})
	}
}

func TestArtifact_Inspect(t *testing.T) {
	tests := []struct {
		name                    string
		filePath                string
		artifactOpt             artifact.Option
		scannerOpt              misconf.ScannerOption
		disabledAnalyzers       []analyzer.Type
		disabledHandlers        []types.HandlerType
		missingBlobsExpectation cache.ArtifactCacheMissingBlobsExpectation
		putBlobExpectation      cache.ArtifactCachePutBlobExpectation
		putArtifactExpectations []cache.ArtifactCachePutArtifactExpectation
		want                    types.ArtifactReference
		wantErr                 string
	}{
		{
			name:     "happy path for raw image",
			filePath: "testdata/AmazonLinux2.img.gz",
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:b8d4a043e24d47c367a2be5bc9749cded56d858a19ad9b19043d99a151cc0050",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: types.OS{
							Family: "amazon",
							Name:   "2 (Karoo)",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "var/lib/rpm/Packages",
								Packages: requiredAmazonLinux2ImgGzPackages,
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:b8d4a043e24d47c367a2be5bc9749cded56d858a19ad9b19043d99a151cc0050",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
						},
					},
				},
			},

			want: types.ArtifactReference{
				Name: "testdata/AmazonLinux2.img.gz",
				Type: types.ArtifactVM,
				ID:   "sha256:b8d4a043e24d47c367a2be5bc9749cded56d858a19ad9b19043d99a151cc0050",
				BlobIDs: []string{
					"sha256:b8d4a043e24d47c367a2be5bc9749cded56d858a19ad9b19043d99a151cc0050",
				},
			},
		},
		{
			name:     "happy path for ebs",
			filePath: "ebs:ebs-012345",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:f26b9c7c836259bd2d11516c755a7aec8e94bbfa7588f98b491bc9b0ca03df73",
					BlobIDs:    []string{"sha256:f26b9c7c836259bd2d11516c755a7aec8e94bbfa7588f98b491bc9b0ca03df73"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:f26b9c7c836259bd2d11516c755a7aec8e94bbfa7588f98b491bc9b0ca03df73",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: types.OS{
							Family: "amazon",
							Name:   "2 (Karoo)",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "var/lib/rpm/Packages",
								Packages: requiredAmazonLinux2ImgGzPackages,
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:f26b9c7c836259bd2d11516c755a7aec8e94bbfa7588f98b491bc9b0ca03df73",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "ebs-012345",
				Type: types.ArtifactVM,
				ID:   "sha256:f26b9c7c836259bd2d11516c755a7aec8e94bbfa7588f98b491bc9b0ca03df73",
				BlobIDs: []string{
					"sha256:f26b9c7c836259bd2d11516c755a7aec8e94bbfa7588f98b491bc9b0ca03df73",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			c.ApplyMissingBlobsExpectation(tt.missingBlobsExpectation)
			c.ApplyPutArtifactExpectations(tt.putArtifactExpectations)
			c.ApplyDeleteBlobsExpectation(cache.ArtifactCacheDeleteBlobsExpectation{
				Args: cache.ArtifactCacheDeleteBlobsArgs{BlobIDsAnything: true},
			})

			filePath := tt.filePath
			if !strings.HasPrefix(tt.filePath, ebsPrefix) {
				filePath = filepath.Join(t.TempDir(), "disk.img")
				testutil.DecompressGzip(t, tt.filePath, filePath)
			}

			a, err := vm.NewArtifact(filePath, c, tt.artifactOpt)
			require.NoError(t, err)

			if aa, ok := a.(*vm.EBS); ok {
				// blockSize: 512 KB, volumeSize: 40MB
				ebs := ebsfile.NewMockEBS("testdata/AmazonLinux2.img.gz", 512<<10, 40<<20)
				aa.SetEBS(ebs)
			}

			got, err := a.Inspect(context.Background())
			defer a.Clean(got)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			tt.want.Name = trimPrefix(filePath)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func trimPrefix(s string) string {
	s = strings.TrimPrefix(s, ebsPrefix)
	s = strings.TrimPrefix(s, filePrefix)
	return s
}

/*
How to create test image with Ubuntu.

# Create empty image
$ dd of=Linux.img count=0 seek=1 bs=41943040

# Create loop device
$ losetup /dev/loop5 Linux.img

# Create partition
$ parted /dev/loop5
(parted)$ mklabel gpt
(parted)$ mkpart primary 1MiB 2MiB
(parted)$ set 1 boot on
(parted)$ mkpart primary xfs 2MiB 100%
(parted)$ quit

# Format XFS and mount
$ mkfs.xfs /dev/loop5p2
$ mount /dev/loop5p2 /mnt/xfs

# Create some files
$ mkdir /mnt/xfs/etc/
$ cp system-release /mnt/xfs/etc/system-release

# Un tup and unmount
$ umount /mnt/xfs
$ losetup -d /dev/loop5
*/
