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
								Packages: expectPackages,
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
								Packages: expectPackages,
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

var expectPackages = []types.Package{
	{ID: "amazon-linux-extras@1.6.7-1.amzn2.noarch", Name: "amazon-linux-extras", Version: "1.6.7", Release: "1.amzn2", Arch: "noarch", SrcName: "amazon-linux-extras", SrcVersion: "1.6.7", Digest: "md5:5ccf2c5afe244577e4dfee0ae17a1932",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64", "system-release@2-10.amzn2.x86_64"}},
	{ID: "basesystem@10.0-7.amzn2.0.1.noarch", Name: "basesystem", Version: "10.0", Release: "7.amzn2.0.1", Arch: "noarch", SrcName: "basesystem", SrcVersion: "10.0", Digest: "md5:d5cd01fe7b2e613d7bdc7d59f434e555",
		SrcRelease: "7.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"filesystem@3.2-25.amzn2.0.4.x86_64", "setup@2.8.71-10.amzn2.noarch"}},
	{ID: "bash@4.2.46-30.amzn2.x86_64", Name: "bash", Version: "4.2.46", Release: "30.amzn2", Arch: "x86_64", SrcName: "bash", SrcVersion: "4.2.46", Digest: "md5:68b4000071366ef00090843892d14c7b",
		SrcRelease: "30.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", Name: "bzip2-libs", Version: "1.0.6", Release: "13.amzn2.0.2", Arch: "x86_64", SrcName: "bzip2", SrcVersion: "1.0.6", Digest: "md5:3b9ca68f8ee5a9ff0aeabcf598146be3",
		SrcRelease: "13.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "ca-certificates@2018.2.22-70.0.amzn2.noarch", Name: "ca-certificates", Version: "2018.2.22", Release: "70.0.amzn2", Arch: "noarch", SrcName: "ca-certificates", SrcVersion: "2018.2.22", Digest: "md5:552d2d83244000639b31d8b4f989046c",
		SrcRelease: "70.0.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "p11-kit-trust@0.23.5-3.amzn2.0.2.x86_64", "p11-kit@0.23.5-3.amzn2.0.2.x86_64"}},
	{ID: "chkconfig@1.7.4-1.amzn2.0.2.x86_64", Name: "chkconfig", Version: "1.7.4", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "chkconfig", SrcVersion: "1.7.4", Digest: "md5:319831087e25271e878170976c7aa68f",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "libsepol@2.5-8.1.amzn2.0.2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64"}},
	{ID: "coreutils@8.22-21.amzn2.x86_64", Name: "coreutils", Version: "8.22", Release: "21.amzn2", Arch: "x86_64", SrcName: "coreutils", SrcVersion: "8.22", Digest: "md5:de9481f791d20868b44579e31dd85a99",
		SrcRelease: "21.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "gmp@6.0.0-15.amzn2.0.2.x86_64", "grep@2.20-3.amzn2.0.2.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libattr@2.4.46-12.amzn2.0.2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "ncurses@6.0-8.20170212.amzn2.1.2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64"}},
	{ID: "cpio@2.11-27.amzn2.x86_64", Name: "cpio", Version: "2.11", Release: "27.amzn2", Arch: "x86_64", SrcName: "cpio", SrcVersion: "2.11", Digest: "md5:d77bff86e64ceac1037be0286c17e017",
		SrcRelease: "27.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "curl@7.61.1-9.amzn2.0.1.x86_64", Name: "curl", Version: "7.61.1", Release: "9.amzn2.0.1", Arch: "x86_64", SrcName: "curl", SrcVersion: "7.61.1", Digest: "md5:0317b4d596110a16ab3676d4544c353b",
		SrcRelease: "9.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libcurl@7.61.1-9.amzn2.0.1.x86_64", "libmetalink@0.1.2-7.amzn2.0.2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "cyrus-sasl-lib@2.1.26-23.amzn2.x86_64", Name: "cyrus-sasl-lib", Version: "2.1.26", Release: "23.amzn2", Arch: "x86_64", SrcName: "cyrus-sasl", SrcVersion: "2.1.26", Digest: "md5:92d13c18e8b678f79738a69d9569dce4",
		SrcRelease: "23.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD with advertising"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "krb5-libs@1.15.1-20.amzn2.0.1.x86_64", "libcom_err@1.42.9-12.amzn2.0.2.x86_64", "libcrypt@2.26-32.amzn2.0.1.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64"}},
	{ID: "diffutils@3.3-4.amzn2.0.2.x86_64", Name: "diffutils", Version: "3.3", Release: "4.amzn2.0.2", Arch: "x86_64", SrcName: "diffutils", SrcVersion: "3.3", Digest: "md5:f296b97a056334481ae92f74b8f6d577",
		SrcRelease: "4.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "info@5.1-5.amzn2.x86_64"}},
	{ID: "elfutils-libelf@0.170-4.amzn2.x86_64", Name: "elfutils-libelf", Version: "0.170", Release: "4.amzn2", Arch: "x86_64", SrcName: "elfutils", SrcVersion: "0.170", Digest: "md5:6c6e86318c10ad19f07447b0b1fb38d6",
		SrcRelease: "4.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+ or LGPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "expat@2.1.0-10.amzn2.0.2.x86_64", Name: "expat", Version: "2.1.0", Release: "10.amzn2.0.2", Arch: "x86_64", SrcName: "expat", SrcVersion: "2.1.0", Digest: "md5:33126f095bf6cbbf7ee9510db6f75388",
		SrcRelease: "10.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "file-libs@5.11-33.amzn2.0.2.x86_64", Name: "file-libs", Version: "5.11", Release: "33.amzn2.0.2", Arch: "x86_64", SrcName: "file", SrcVersion: "5.11", Digest: "md5:ddb69b5affeef21de02c9c25e2feabf5",
		SrcRelease: "33.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "filesystem@3.2-25.amzn2.0.4.x86_64", Name: "filesystem", Version: "3.2", Release: "25.amzn2.0.4", Arch: "x86_64", SrcName: "filesystem", SrcVersion: "3.2", Digest: "md5:cbe6a498033d9ce077e518ff27f5a7f2",
		SrcRelease: "25.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "setup@2.8.71-10.amzn2.noarch"}},
	{ID: "findutils@4.5.11-5.amzn2.0.2.x86_64", Name: "findutils", Version: "4.5.11", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "findutils", SrcVersion: "4.5.11", Digest: "md5:f0b6cc2af7766880194cf93dfabb06b7",
		SrcRelease: "5.amzn2.0.2", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64"}},
	{ID: "gawk@4.0.2-4.amzn2.1.2.x86_64", Name: "gawk", Version: "4.0.2", Release: "4.amzn2.1.2", Arch: "x86_64", SrcName: "gawk", SrcVersion: "4.0.2", Digest: "md5:bd527581072901ea4b66025e04a5b8b4",
		SrcRelease: "4.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+ and GPL and LGPLv3+ and LGPL and BSD"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "gdbm@1.13-6.amzn2.0.2.x86_64", Name: "gdbm", Version: "1.13", Release: "6.amzn2.0.2", Arch: "x86_64", SrcName: "gdbm", SrcVersion: "1.13", Digest: "md5:75545ede3a19d8f68cb408317a4d1384",
		SrcRelease: "6.amzn2.0.2", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "readline@6.2-10.amzn2.0.2.x86_64"}},
	{ID: "glib2@2.54.2-2.amzn2.x86_64", Name: "glib2", Version: "2.54.2", Release: "2.amzn2", Arch: "x86_64", SrcName: "glib2", SrcVersion: "2.54.2", Digest: "md5:607e2abde3a16232421df9a40fe56d88",
		SrcRelease: "2.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libffi@3.0.13-18.amzn2.0.2.x86_64", "libgcc@7.3.1-5.amzn2.0.2.x86_64", "libmount@2.30.2-2.amzn2.0.4.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "pcre@8.32-17.amzn2.0.2.x86_64", "shared-mime-info@1.8-4.amzn2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "glibc@2.26-32.amzn2.0.1.x86_64", Name: "glibc", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26", Digest: "md5:bf2057b039cd1b2fdcc953b9273ffa2c",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"basesystem@10.0-7.amzn2.0.1.noarch", "glibc-common@2.26-32.amzn2.0.1.x86_64", "glibc-minimal-langpack@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "glibc-common@2.26-32.amzn2.0.1.x86_64", Name: "glibc-common", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26", Digest: "md5:7158c72a39690b529b2ef57c02be5de7",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "tzdata@2018i-1.amzn2.noarch"}},
	{ID: "glibc-langpack-en@2.26-32.amzn2.0.1.x86_64", Name: "glibc-langpack-en", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26", Digest: "md5:05208c19fc8308823f2a26544214fcc8",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"glibc-common@2.26-32.amzn2.0.1.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "glibc-minimal-langpack@2.26-32.amzn2.0.1.x86_64", Name: "glibc-minimal-langpack", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26", Digest: "md5:753d1f56c8233e1968dfdacf7b358b9e",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"glibc-common@2.26-32.amzn2.0.1.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "gmp@6.0.0-15.amzn2.0.2.x86_64", Name: "gmp", Version: "6.0.0", Release: "15.amzn2.0.2", Arch: "x86_64", SrcName: "gmp", SrcVersion: "6.0.0", Digest: "md5:b8c7bcf34b734beab4e390f4efdc22a0",
		SrcRelease: "15.amzn2.0.2", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv3+ or GPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgcc@7.3.1-5.amzn2.0.2.x86_64", "libstdc++@7.3.1-5.amzn2.0.2.x86_64"}},
	{ID: "gnupg2@2.0.22-5.amzn2.0.3.x86_64", Name: "gnupg2", Version: "2.0.22", Release: "5.amzn2.0.3", Arch: "x86_64", SrcName: "gnupg2", SrcVersion: "2.0.22", Digest: "md5:c863242be21abaadec187a903e5cc64d",
		SrcRelease: "5.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libassuan@2.1.0-3.amzn2.0.2.x86_64", "libcurl@7.61.1-9.amzn2.0.1.x86_64", "libgcrypt@1.5.3-14.amzn2.0.2.x86_64", "libgpg-error@1.12-3.amzn2.0.3.x86_64", "openldap@2.4.44-15.amzn2.x86_64", "pinentry@0.8.1-17.amzn2.0.2.x86_64", "pth@2.0.7-23.amzn2.0.2.x86_64", "readline@6.2-10.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "gpg-pubkey@c87f5b1a-593863f8.", Name: "gpg-pubkey", Version: "c87f5b1a", Release: "593863f8", Arch: "None", SrcName: "", SrcVersion: "", Digest: "",
		SrcRelease: "", Epoch: 0, SrcEpoch: 0, Maintainer: "", Layer: types.Layer{}, Licenses: []string{"pubkey"}},
	{ID: "gpgme@1.3.2-5.amzn2.0.2.x86_64", Name: "gpgme", Version: "1.3.2", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "gpgme", SrcVersion: "1.3.2", Digest: "md5:ef455499b16c9310990ed661295e9bae",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "gnupg2@2.0.22-5.amzn2.0.3.x86_64", "libassuan@2.1.0-3.amzn2.0.2.x86_64", "libgpg-error@1.12-3.amzn2.0.3.x86_64"}},
	{ID: "grep@2.20-3.amzn2.0.2.x86_64", Name: "grep", Version: "2.20", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "grep", SrcVersion: "2.20", Digest: "md5:0fbe0a134668452e0b20be9ea1ef7c14",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "pcre@8.32-17.amzn2.0.2.x86_64"}},
	{ID: "info@5.1-5.amzn2.x86_64", Name: "info", Version: "5.1", Release: "5.amzn2", Arch: "x86_64", SrcName: "texinfo", SrcVersion: "5.1", Digest: "md5:6036dfc4c53336873524488fe5002e4c",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "keyutils-libs@1.5.8-3.amzn2.0.2.x86_64", Name: "keyutils-libs", Version: "1.5.8", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "keyutils", SrcVersion: "1.5.8", Digest: "md5:4aff48d8c9f97b21c61402d9d9840b22",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+ and LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "krb5-libs@1.15.1-20.amzn2.0.1.x86_64", Name: "krb5-libs", Version: "1.15.1", Release: "20.amzn2.0.1", Arch: "x86_64", SrcName: "krb5", SrcVersion: "1.15.1", Digest: "md5:8d86f1bd485258ce1d5f87ce763e1439",
		SrcRelease: "20.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "gawk@4.0.2-4.amzn2.1.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "grep@2.20-3.amzn2.0.2.x86_64", "keyutils-libs@1.5.8-3.amzn2.0.2.x86_64", "libcom_err@1.42.9-12.amzn2.0.2.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "libverto@0.2.5-4.amzn2.0.2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "sed@4.2.2-5.amzn2.0.2.x86_64"}},
	{ID: "libacl@2.2.51-14.amzn2.x86_64", Name: "libacl", Version: "2.2.51", Release: "14.amzn2", Arch: "x86_64", SrcName: "acl", SrcVersion: "2.2.51", Digest: "md5:6d4ffe4e28af5d6bf9c6bc50ef4ecb5a",
		SrcRelease: "14.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libattr@2.4.46-12.amzn2.0.2.x86_64"}},
	{ID: "libassuan@2.1.0-3.amzn2.0.2.x86_64", Name: "libassuan", Version: "2.1.0", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "libassuan", SrcVersion: "2.1.0", Digest: "md5:f02a57d69476bd9b73cda0142a2ecf94",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and GPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgpg-error@1.12-3.amzn2.0.3.x86_64"}},
	{ID: "libattr@2.4.46-12.amzn2.0.2.x86_64", Name: "libattr", Version: "2.4.46", Release: "12.amzn2.0.2", Arch: "x86_64", SrcName: "attr", SrcVersion: "2.4.46", Digest: "md5:af982fde74b4c52e53db6b41ebe87a62",
		SrcRelease: "12.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libblkid@2.30.2-2.amzn2.0.4.x86_64", Name: "libblkid", Version: "2.30.2", Release: "2.amzn2.0.4", Arch: "x86_64", SrcName: "util-linux", SrcVersion: "2.30.2", Digest: "md5:7e167ad8f8bd02e0958d53b356de495e",
		SrcRelease: "2.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libuuid@2.30.2-2.amzn2.0.4.x86_64"}},
	{ID: "libcap@2.22-9.amzn2.0.2.x86_64", Name: "libcap", Version: "2.22", Release: "9.amzn2.0.2", Arch: "x86_64", SrcName: "libcap", SrcVersion: "2.22", Digest: "md5:5cab5f26f0c9bcf0d212d02a121569bb",
		SrcRelease: "9.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libattr@2.4.46-12.amzn2.0.2.x86_64"}},
	{ID: "libcom_err@1.42.9-12.amzn2.0.2.x86_64", Name: "libcom_err", Version: "1.42.9", Release: "12.amzn2.0.2", Arch: "x86_64", SrcName: "e2fsprogs", SrcVersion: "1.42.9", Digest: "md5:fb7a8406d3178cea46d1fe77f5a9a30b",
		SrcRelease: "12.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libcrypt@2.26-32.amzn2.0.1.x86_64", Name: "libcrypt", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26", Digest: "md5:4c177eb85ada2e38684b47239229bb87",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libcurl@7.61.1-9.amzn2.0.1.x86_64", Name: "libcurl", Version: "7.61.1", Release: "9.amzn2.0.1", Arch: "x86_64", SrcName: "curl", SrcVersion: "7.61.1", Digest: "md5:9910c3ec3bb18786aee78def8b693ee3",
		SrcRelease: "9.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "krb5-libs@1.15.1-20.amzn2.0.1.x86_64", "libcom_err@1.42.9-12.amzn2.0.2.x86_64", "libidn2@2.0.4-1.amzn2.0.2.x86_64", "libnghttp2@1.31.1-1.amzn2.0.2.x86_64", "libssh2@1.4.3-12.amzn2.2.x86_64", "nss-pem@1.0.3-5.amzn2.x86_64", "openldap@2.4.44-15.amzn2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "libdb@5.3.21-24.amzn2.0.3.x86_64", Name: "libdb", Version: "5.3.21", Release: "24.amzn2.0.3", Arch: "x86_64", SrcName: "libdb", SrcVersion: "5.3.21", Digest: "md5:c3bb75ae2a6d8e2e7009ec11feb6c9bb",
		SrcRelease: "24.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD and LGPLv2 and Sleepycat"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libdb-utils@5.3.21-24.amzn2.0.3.x86_64", Name: "libdb-utils", Version: "5.3.21", Release: "24.amzn2.0.3", Arch: "x86_64", SrcName: "libdb", SrcVersion: "5.3.21", Digest: "md5:0c5f0675aedd086cc42cfe8215e6f705",
		SrcRelease: "24.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD and LGPLv2 and Sleepycat"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64"}},
	{ID: "libffi@3.0.13-18.amzn2.0.2.x86_64", Name: "libffi", Version: "3.0.13", Release: "18.amzn2.0.2", Arch: "x86_64", SrcName: "libffi", SrcVersion: "3.0.13", Digest: "md5:0e6cb3903e3a43a5d57b4ccf8d4b2343",
		SrcRelease: "18.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT and Public Domain"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libgcc@7.3.1-5.amzn2.0.2.x86_64", Name: "libgcc", Version: "7.3.1", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "gcc", SrcVersion: "7.3.1", Digest: "md5:5f70f5c9970978281a3b36b9d1631c8a",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libgcrypt@1.5.3-14.amzn2.0.2.x86_64", Name: "libgcrypt", Version: "1.5.3", Release: "14.amzn2.0.2", Arch: "x86_64", SrcName: "libgcrypt", SrcVersion: "1.5.3", Digest: "md5:edb6b42f38b04ec0c7b067f8bcad36e1",
		SrcRelease: "14.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgpg-error@1.12-3.amzn2.0.3.x86_64"}},
	{ID: "libgpg-error@1.12-3.amzn2.0.3.x86_64", Name: "libgpg-error", Version: "1.12", Release: "3.amzn2.0.3", Arch: "x86_64", SrcName: "libgpg-error", SrcVersion: "1.12", Digest: "md5:627d36123c310b3cae17b241230eb4cb",
		SrcRelease: "3.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libidn2@2.0.4-1.amzn2.0.2.x86_64", Name: "libidn2", Version: "2.0.4", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "libidn2", SrcVersion: "2.0.4", Digest: "md5:ca6d94f46b1cb8ef89d409b119e7ebae",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"(GPLv2+ or LGPLv3+) and GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libunistring@0.9.3-9.amzn2.0.2.x86_64"}},
	{ID: "libmetalink@0.1.2-7.amzn2.0.2.x86_64", Name: "libmetalink", Version: "0.1.2", Release: "7.amzn2.0.2", Arch: "x86_64", SrcName: "libmetalink", SrcVersion: "0.1.2", Digest: "md5:25b494f9388c7356357ef03ca3f5e736",
		SrcRelease: "7.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"expat@2.1.0-10.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libmount@2.30.2-2.amzn2.0.4.x86_64", Name: "libmount", Version: "2.30.2", Release: "2.amzn2.0.4", Arch: "x86_64", SrcName: "util-linux", SrcVersion: "2.30.2", Digest: "md5:705b02012e4e1eeef6df339904cc215d",
		SrcRelease: "2.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libblkid@2.30.2-2.amzn2.0.4.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "libuuid@2.30.2-2.amzn2.0.4.x86_64"}},
	{ID: "libnghttp2@1.31.1-1.amzn2.0.2.x86_64", Name: "libnghttp2", Version: "1.31.1", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "nghttp2", SrcVersion: "1.31.1", Digest: "md5:69886acb5bbb2fe09c49ee83cd1ec24f",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libselinux@2.5-12.amzn2.0.2.x86_64", Name: "libselinux", Version: "2.5", Release: "12.amzn2.0.2", Arch: "x86_64", SrcName: "libselinux", SrcVersion: "2.5", Digest: "md5:954ef0208b12caa56715a3b2f7c277f8",
		SrcRelease: "12.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libsepol@2.5-8.1.amzn2.0.2.x86_64", "pcre@8.32-17.amzn2.0.2.x86_64"}},
	{ID: "libsepol@2.5-8.1.amzn2.0.2.x86_64", Name: "libsepol", Version: "2.5", Release: "8.1.amzn2.0.2", Arch: "x86_64", SrcName: "libsepol", SrcVersion: "2.5", Digest: "md5:1fa1348aaa1bbe2445e04a8755b0deec",
		SrcRelease: "8.1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libssh2@1.4.3-12.amzn2.2.x86_64", Name: "libssh2", Version: "1.4.3", Release: "12.amzn2.2", Arch: "x86_64", SrcName: "libssh2", SrcVersion: "1.4.3", Digest: "md5:33f784f10580e22d3a6ba84945796960",
		SrcRelease: "12.amzn2.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "libstdc++@7.3.1-5.amzn2.0.2.x86_64", Name: "libstdc++", Version: "7.3.1", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "gcc", SrcVersion: "7.3.1", Digest: "md5:9761f5e7a2bbba273077e7c4be561183",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgcc@7.3.1-5.amzn2.0.2.x86_64"}},
	{ID: "libtasn1@4.10-1.amzn2.0.2.x86_64", Name: "libtasn1", Version: "4.10", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "libtasn1", SrcVersion: "4.10", Digest: "md5:f86768450911add6cc7e24efe55ea316",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+ and LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libunistring@0.9.3-9.amzn2.0.2.x86_64", Name: "libunistring", Version: "0.9.3", Release: "9.amzn2.0.2", Arch: "x86_64", SrcName: "libunistring", SrcVersion: "0.9.3", Digest: "md5:950a12402cb9c17357c3443e403e13e2",
		SrcRelease: "9.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "info@5.1-5.amzn2.x86_64"}},
	{ID: "libuuid@2.30.2-2.amzn2.0.4.x86_64", Name: "libuuid", Version: "2.30.2", Release: "2.amzn2.0.4", Arch: "x86_64", SrcName: "util-linux", SrcVersion: "2.30.2", Digest: "md5:99553912c486dee59484dbd87be0bc47",
		SrcRelease: "2.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libverto@0.2.5-4.amzn2.0.2.x86_64", Name: "libverto", Version: "0.2.5", Release: "4.amzn2.0.2", Arch: "x86_64", SrcName: "libverto", SrcVersion: "0.2.5", Digest: "md5:f7b3291c57a168710227c6a6cd491b13",
		SrcRelease: "4.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libxml2@2.9.1-6.amzn2.3.2.x86_64", Name: "libxml2", Version: "2.9.1", Release: "6.amzn2.3.2", Arch: "x86_64", SrcName: "libxml2", SrcVersion: "2.9.1", Digest: "md5:4c2a321ae7d954ef0dbd52c357febb80",
		SrcRelease: "6.amzn2.3.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "lua@5.1.4-15.amzn2.0.2.x86_64", Name: "lua", Version: "5.1.4", Release: "15.amzn2.0.2", Arch: "x86_64", SrcName: "lua", SrcVersion: "5.1.4", Digest: "md5:5040468c8014e6489da9342c24d04cd2",
		SrcRelease: "15.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "readline@6.2-10.amzn2.0.2.x86_64"}},
	{ID: "ncurses@6.0-8.20170212.amzn2.1.2.x86_64", Name: "ncurses", Version: "6.0", Release: "8.20170212.amzn2.1.2", Arch: "x86_64", SrcName: "ncurses", SrcVersion: "6.0", Digest: "md5:b868e8d7015907bed13f86d62fc518a1",
		SrcRelease: "8.20170212.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "ncurses-base@6.0-8.20170212.amzn2.1.2.noarch", Name: "ncurses-base", Version: "6.0", Release: "8.20170212.amzn2.1.2", Arch: "noarch", SrcName: "ncurses", SrcVersion: "6.0", Digest: "md5:d6ef4a714a27ce5167f32f386a8a6255",
		SrcRelease: "8.20170212.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{ID: "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", Name: "ncurses-libs", Version: "6.0", Release: "8.20170212.amzn2.1.2", Arch: "x86_64", SrcName: "ncurses", SrcVersion: "6.0", Digest: "md5:561d03b5f96c3d072ac190aed9b9d622",
		SrcRelease: "8.20170212.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-base@6.0-8.20170212.amzn2.1.2.noarch"}},
	{ID: "nspr@4.19.0-1.amzn2.x86_64", Name: "nspr", Version: "4.19.0", Release: "1.amzn2", Arch: "x86_64", SrcName: "nspr", SrcVersion: "4.19.0", Digest: "md5:28a567fa777d1814c46ccf28dd834951",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "nss@3.36.0-7.amzn2.x86_64", Name: "nss", Version: "3.36.0", Release: "7.amzn2", Arch: "x86_64", SrcName: "nss", SrcVersion: "3.36.0", Digest: "md5:7fde87396441125f3ab281042fc22c68",
		SrcRelease: "7.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-pem@1.0.3-5.amzn2.x86_64", "nss-softokn@3.36.0-5.amzn2.x86_64", "nss-sysinit@3.36.0-7.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64"}},
	{ID: "nss-pem@1.0.3-5.amzn2.x86_64", Name: "nss-pem", Version: "1.0.3", Release: "5.amzn2", Arch: "x86_64", SrcName: "nss-pem", SrcVersion: "1.0.3", Digest: "md5:34c3acc3e650bc7ba7fc55e03669031c",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv1.1"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "nss@3.36.0-7.amzn2.x86_64"}},
	{ID: "nss-softokn@3.36.0-5.amzn2.x86_64", Name: "nss-softokn", Version: "3.36.0", Release: "5.amzn2", Arch: "x86_64", SrcName: "nss-softokn", SrcVersion: "3.36.0", Digest: "md5:8b4f6d67af2366a07504b4a9c93b6990",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-softokn-freebl@3.36.0-5.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "sqlite@3.7.17-8.amzn2.0.2.x86_64"}},
	{ID: "nss-softokn-freebl@3.36.0-5.amzn2.x86_64", Name: "nss-softokn-freebl", Version: "3.36.0", Release: "5.amzn2", Arch: "x86_64", SrcName: "nss-softokn", SrcVersion: "3.36.0", Digest: "md5:36190db9c194a42a4a01243d02f4f7be",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64"}},
	{ID: "nss-sysinit@3.36.0-7.amzn2.x86_64", Name: "nss-sysinit", Version: "3.36.0", Release: "7.amzn2", Arch: "x86_64", SrcName: "nss", SrcVersion: "3.36.0", Digest: "md5:97ce671238c4d518fa7e5cdc01b81d7f",
		SrcRelease: "7.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "sed@4.2.2-5.amzn2.0.2.x86_64"}},
	{ID: "nss-tools@3.36.0-7.amzn2.x86_64", Name: "nss-tools", Version: "3.36.0", Release: "7.amzn2", Arch: "x86_64", SrcName: "nss", SrcVersion: "3.36.0", Digest: "md5:d393d5bb2bbc0a5468dd07c748fc400b",
		SrcRelease: "7.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-softokn@3.36.0-5.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "nss-util@3.36.0-1.amzn2.x86_64", Name: "nss-util", Version: "3.36.0", Release: "1.amzn2", Arch: "x86_64", SrcName: "nss-util", SrcVersion: "3.36.0", Digest: "md5:89652ed4e3ccda044d79807f75604cb2",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64"}},
	{ID: "openldap@2.4.44-15.amzn2.x86_64", Name: "openldap", Version: "2.4.44", Release: "15.amzn2", Arch: "x86_64", SrcName: "openldap", SrcVersion: "2.4.44", Digest: "md5:4c5d6599e1682399af1c5ecca3e55511",
		SrcRelease: "15.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"OpenLDAP"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "cyrus-sasl-lib@2.1.26-23.amzn2.x86_64", "findutils@4.5.11-5.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-tools@3.36.0-7.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "rpm@4.11.3-25.amzn2.0.3.x86_64"}},
	{ID: "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", Name: "openssl-libs", Version: "1.0.2k", Release: "16.amzn2.1.1", Arch: "x86_64", SrcName: "openssl", SrcVersion: "1.0.2k", Digest: "md5:4752bec1104676e41f280e13e0b9eb2e",
		SrcRelease: "16.amzn2.1.1", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"OpenSSL"}, DependsOn: []string{"ca-certificates@2018.2.22-70.0.amzn2.noarch", "glibc@2.26-32.amzn2.0.1.x86_64", "krb5-libs@1.15.1-20.amzn2.0.1.x86_64", "libcom_err@1.42.9-12.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "p11-kit@0.23.5-3.amzn2.0.2.x86_64", Name: "p11-kit", Version: "0.23.5", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "p11-kit", SrcVersion: "0.23.5", Digest: "md5:b34a666b479cc3129b3abf51a6e6dd2d",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libffi@3.0.13-18.amzn2.0.2.x86_64"}},
	{ID: "p11-kit-trust@0.23.5-3.amzn2.0.2.x86_64", Name: "p11-kit-trust", Version: "0.23.5", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "p11-kit", SrcVersion: "0.23.5", Digest: "md5:831861096403858d27fdb833ed8f9e4d",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libffi@3.0.13-18.amzn2.0.2.x86_64", "libtasn1@4.10-1.amzn2.0.2.x86_64", "nss-softokn-freebl@3.36.0-5.amzn2.x86_64", "p11-kit@0.23.5-3.amzn2.0.2.x86_64"}},
	{ID: "pcre@8.32-17.amzn2.0.2.x86_64", Name: "pcre", Version: "8.32", Release: "17.amzn2.0.2", Arch: "x86_64", SrcName: "pcre", SrcVersion: "8.32", Digest: "md5:a4928c8f2c44aec091517713997cbb18",
		SrcRelease: "17.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgcc@7.3.1-5.amzn2.0.2.x86_64", "libstdc++@7.3.1-5.amzn2.0.2.x86_64"}},
	{ID: "pinentry@0.8.1-17.amzn2.0.2.x86_64", Name: "pinentry", Version: "0.8.1", Release: "17.amzn2.0.2", Arch: "x86_64", SrcName: "pinentry", SrcVersion: "0.8.1", Digest: "md5:b8ecb8d8b485458190167157bb762a02",
		SrcRelease: "17.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "popt@1.13-16.amzn2.0.2.x86_64", Name: "popt", Version: "1.13", Release: "16.amzn2.0.2", Arch: "x86_64", SrcName: "popt", SrcVersion: "1.13", Digest: "md5:c02f99f24f3a4bb86d307cf4e3609e2f",
		SrcRelease: "16.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "pth@2.0.7-23.amzn2.0.2.x86_64", Name: "pth", Version: "2.0.7", Release: "23.amzn2.0.2", Arch: "x86_64", SrcName: "pth", SrcVersion: "2.0.7", Digest: "md5:aebfe45c88d371858a9bd51f42ce3dcf",
		SrcRelease: "23.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "pygpgme@0.3-9.amzn2.0.2.x86_64", Name: "pygpgme", Version: "0.3", Release: "9.amzn2.0.2", Arch: "x86_64", SrcName: "pygpgme", SrcVersion: "0.3", Digest: "md5:1127b357ec1684b47606002c32635a1b",
		SrcRelease: "9.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "gpgme@1.3.2-5.amzn2.0.2.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "pyliblzma@0.5.3-11.amzn2.0.2.x86_64", Name: "pyliblzma", Version: "0.5.3", Release: "11.amzn2.0.2", Arch: "x86_64", SrcName: "pyliblzma", SrcVersion: "0.5.3", Digest: "md5:1dbb7a94a790da23ef846fc920da5b49",
		SrcRelease: "11.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64"}},
	{ID: "python@2.7.14-58.amzn2.0.4.x86_64", Name: "python", Version: "2.7.14", Release: "58.amzn2.0.4", Arch: "x86_64", SrcName: "python", SrcVersion: "2.7.14", Digest: "md5:93bd4017a271f50e9cfa181b6749d2f2",
		SrcRelease: "58.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Python"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "python-iniparse@0.4-9.amzn2.noarch", Name: "python-iniparse", Version: "0.4", Release: "9.amzn2", Arch: "noarch", SrcName: "python-iniparse", SrcVersion: "0.4", Digest: "md5:f7458aafcf07328adae7ba322cf0fb97",
		SrcRelease: "9.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "python-libs@2.7.14-58.amzn2.0.4.x86_64", Name: "python-libs", Version: "2.7.14", Release: "58.amzn2.0.4", Arch: "x86_64", SrcName: "python", SrcVersion: "2.7.14", Digest: "md5:61927a63008fcd500d58d01b6b0354ed",
		SrcRelease: "58.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Python"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "expat@2.1.0-10.amzn2.0.2.x86_64", "gdbm@1.13-6.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libcrypt@2.26-32.amzn2.0.1.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libffi@3.0.13-18.amzn2.0.2.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "readline@6.2-10.amzn2.0.2.x86_64", "sqlite@3.7.17-8.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "python-pycurl@7.19.0-19.amzn2.0.2.x86_64", Name: "python-pycurl", Version: "7.19.0", Release: "19.amzn2.0.2", Arch: "x86_64", SrcName: "python-pycurl", SrcVersion: "7.19.0", Digest: "md5:335aa2c10fa48a609071cd2896360905",
		SrcRelease: "19.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ or MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "keyutils-libs@1.5.8-3.amzn2.0.2.x86_64", "libcurl@7.61.1-9.amzn2.0.1.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "python-urlgrabber@3.10-8.amzn2.noarch", Name: "python-urlgrabber", Version: "3.10", Release: "8.amzn2", Arch: "noarch", SrcName: "python-urlgrabber", SrcVersion: "3.10", Digest: "md5:da222474d27b0837d5403e8feda4894f",
		SrcRelease: "8.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"python-pycurl@7.19.0-19.amzn2.0.2.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "pyxattr@0.5.1-5.amzn2.0.2.x86_64", Name: "pyxattr", Version: "0.5.1", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "pyxattr", SrcVersion: "0.5.1", Digest: "md5:614efafa56e6136505bf6a09b2257d02",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libattr@2.4.46-12.amzn2.0.2.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "readline@6.2-10.amzn2.0.2.x86_64", Name: "readline", Version: "6.2", Release: "10.amzn2.0.2", Arch: "x86_64", SrcName: "readline", SrcVersion: "6.2", Digest: "md5:54e40557d09a8a0c3bfd83e0b03c4b2b",
		SrcRelease: "10.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "rpm@4.11.3-25.amzn2.0.3.x86_64", Name: "rpm", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3", Digest: "md5:a6430cf39925fb4833d1868a8b2fb59c",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "curl@7.61.1-9.amzn2.0.1.x86_64", "elfutils-libelf@0.170-4.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "lua@5.1.4-15.amzn2.0.2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64", "rpm-libs@4.11.3-25.amzn2.0.3.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "rpm-build-libs@4.11.3-25.amzn2.0.3.x86_64", Name: "rpm-build-libs", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3", Digest: "md5:8ddffea33bf69c06e45570525614fbec",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+ and LGPLv2+ with exceptions"}, DependsOn: []string{"bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "elfutils-libelf@0.170-4.amzn2.x86_64", "file-libs@5.11-33.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "lua@5.1.4-15.amzn2.0.2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64", "rpm-libs@4.11.3-25.amzn2.0.3.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "rpm-libs@4.11.3-25.amzn2.0.3.x86_64", Name: "rpm-libs", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3", Digest: "md5:84906c2d68928f69d55d7147d822e032",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+ and LGPLv2+ with exceptions"}, DependsOn: []string{"bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "elfutils-libelf@0.170-4.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "lua@5.1.4-15.amzn2.0.2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64", "rpm@4.11.3-25.amzn2.0.3.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "rpm-python@4.11.3-25.amzn2.0.3.x86_64", Name: "rpm-python", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3", Digest: "md5:18ce89b25d0eda0458e8aca000ec2a46",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "elfutils-libelf@0.170-4.amzn2.x86_64", "file-libs@5.11-33.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "lua@5.1.4-15.amzn2.0.2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64", "rpm-build-libs@4.11.3-25.amzn2.0.3.x86_64", "rpm-libs@4.11.3-25.amzn2.0.3.x86_64", "rpm@4.11.3-25.amzn2.0.3.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "sed@4.2.2-5.amzn2.0.2.x86_64", Name: "sed", Version: "4.2.2", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "sed", SrcVersion: "4.2.2", Digest: "md5:65537e75100a96b0fd7981985a0534e2",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64"}},
	{ID: "setup@2.8.71-10.amzn2.noarch", Name: "setup", Version: "2.8.71", Release: "10.amzn2", Arch: "noarch", SrcName: "setup", SrcVersion: "2.8.71", Digest: "md5:1f615c549bd41ece8daee63a9aac6ad8",
		SrcRelease: "10.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"system-release@2-10.amzn2.x86_64"}},
	{ID: "shared-mime-info@1.8-4.amzn2.x86_64", Name: "shared-mime-info", Version: "1.8", Release: "4.amzn2", Arch: "x86_64", SrcName: "shared-mime-info", SrcVersion: "1.8", Digest: "md5:fdffe88dd6ce8d20c9916cb057010377",
		SrcRelease: "4.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "glib2@2.54.2-2.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libxml2@2.9.1-6.amzn2.3.2.x86_64"}},
	{ID: "sqlite@3.7.17-8.amzn2.0.2.x86_64", Name: "sqlite", Version: "3.7.17", Release: "8.amzn2.0.2", Arch: "x86_64", SrcName: "sqlite", SrcVersion: "3.7.17", Digest: "md5:2e333b90b67873f4ba106f022c3aac12",
		SrcRelease: "8.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "readline@6.2-10.amzn2.0.2.x86_64"}},
	{ID: "system-release@2-10.amzn2.x86_64", Name: "system-release", Version: "2", Release: "10.amzn2", Arch: "x86_64", SrcName: "system-release", SrcVersion: "2", Digest: "md5:8c0ec2bd29eb0bac9fbfbf8b05081551",
		SrcRelease: "10.amzn2", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64"}},
	{ID: "tzdata@2018i-1.amzn2.noarch", Name: "tzdata", Version: "2018i", Release: "1.amzn2", Arch: "noarch", SrcName: "tzdata", SrcVersion: "2018i", Digest: "md5:5d09cc0ab578c96f4273882ce3d9ef5d",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}},
	{ID: "vim-minimal@7.4.160-4.amzn2.0.16.x86_64", Name: "vim-minimal", Version: "7.4.160", Release: "4.amzn2.0.16", Arch: "x86_64", SrcName: "vim", SrcVersion: "7.4.160", Digest: "md5:3c078dff118c0d78c041d65fcede791b",
		SrcRelease: "4.amzn2.0.16", Epoch: 2, SrcEpoch: 2, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Vim"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "xz-libs@5.2.2-1.amzn2.0.2.x86_64", Name: "xz-libs", Version: "5.2.2", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "xz", SrcVersion: "5.2.2", Digest: "md5:6bb8b8178abe1ef207c50f850f5afe27",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "yum@3.4.3-158.amzn2.0.2.noarch", Name: "yum", Version: "3.4.3", Release: "158.amzn2.0.2", Arch: "noarch", SrcName: "yum", SrcVersion: "3.4.3", Digest: "md5:f3dfa0037c8a8cb0dc2c4d3d822df1b2",
		SrcRelease: "158.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"cpio@2.11-27.amzn2.x86_64", "diffutils@3.3-4.amzn2.0.2.x86_64", "pygpgme@0.3-9.amzn2.0.2.x86_64", "pyliblzma@0.5.3-11.amzn2.0.2.x86_64", "python-iniparse@0.4-9.amzn2.noarch", "python-urlgrabber@3.10-8.amzn2.noarch", "python@2.7.14-58.amzn2.0.4.x86_64", "pyxattr@0.5.1-5.amzn2.0.2.x86_64", "rpm-python@4.11.3-25.amzn2.0.3.x86_64", "rpm@4.11.3-25.amzn2.0.3.x86_64", "yum-metadata-parser@1.1.4-10.amzn2.0.2.x86_64"}},
	{ID: "yum-metadata-parser@1.1.4-10.amzn2.0.2.x86_64", Name: "yum-metadata-parser", Version: "1.1.4", Release: "10.amzn2.0.2", Arch: "x86_64", SrcName: "yum-metadata-parser", SrcVersion: "1.1.4", Digest: "md5:7bdc1705d349f61a65015726852919a4",
		SrcRelease: "10.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2"}, DependsOn: []string{"glib2@2.54.2-2.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libxml2@2.9.1-6.amzn2.3.2.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64", "sqlite@3.7.17-8.amzn2.0.2.x86_64"}},
	{ID: "yum-plugin-ovl@1.1.31-46.amzn2.0.1.noarch", Name: "yum-plugin-ovl", Version: "1.1.31", Release: "46.amzn2.0.1", Arch: "noarch", SrcName: "yum-utils", SrcVersion: "1.1.31", Digest: "md5:c39c00494ee1cf1652a6eddbecb3f5a8",
		SrcRelease: "46.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"yum@3.4.3-158.amzn2.0.2.noarch"}},
	{ID: "yum-plugin-priorities@1.1.31-46.amzn2.0.1.noarch", Name: "yum-plugin-priorities", Version: "1.1.31", Release: "46.amzn2.0.1", Arch: "noarch", SrcName: "yum-utils", SrcVersion: "1.1.31", Digest: "md5:7088899bd777f1641e01511db7e20b13",
		SrcRelease: "46.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"yum@3.4.3-158.amzn2.0.2.noarch"}},
	{ID: "zlib@1.2.7-17.amzn2.0.2.x86_64", Name: "zlib", Version: "1.2.7", Release: "17.amzn2.0.2", Arch: "x86_64", SrcName: "zlib", SrcVersion: "1.2.7", Digest: "md5:b6736d2fe1fa3106608e5d38d144ea2a",
		SrcRelease: "17.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"zlib and Boost"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
}
