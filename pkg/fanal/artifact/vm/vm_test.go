package vm_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	ebsfile "github.com/masahiro331/go-ebs-file"

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
		scannerOpt              config.ScannerOption
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
					BlobID: "sha256:bdff805a4b2a96074c549dbb7912f5089df1a484cf0919639ecdba437a959e90",
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
						ArtifactID: "sha256:bdff805a4b2a96074c549dbb7912f5089df1a484cf0919639ecdba437a959e90",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
						},
					},
				},
			},

			want: types.ArtifactReference{
				Name: "testdata/AmazonLinux2.img.gz",
				Type: types.ArtifactVM,
				ID:   "sha256:bdff805a4b2a96074c549dbb7912f5089df1a484cf0919639ecdba437a959e90",
				BlobIDs: []string{
					"sha256:bdff805a4b2a96074c549dbb7912f5089df1a484cf0919639ecdba437a959e90",
				},
			},
		},
		{
			name:     "happy path for ebs",
			filePath: "ebs:ebs-012345",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:284fbc20c2224e9ffc9dbc2fa1cdc4138fcfd5c55763ecb737864c0ee0d8163f",
					BlobIDs:    []string{"sha256:284fbc20c2224e9ffc9dbc2fa1cdc4138fcfd5c55763ecb737864c0ee0d8163f"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:284fbc20c2224e9ffc9dbc2fa1cdc4138fcfd5c55763ecb737864c0ee0d8163f",
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
						ArtifactID: "sha256:284fbc20c2224e9ffc9dbc2fa1cdc4138fcfd5c55763ecb737864c0ee0d8163f",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "ebs-012345",
				Type: types.ArtifactVM,
				ID:   "sha256:284fbc20c2224e9ffc9dbc2fa1cdc4138fcfd5c55763ecb737864c0ee0d8163f",
				BlobIDs: []string{
					"sha256:284fbc20c2224e9ffc9dbc2fa1cdc4138fcfd5c55763ecb737864c0ee0d8163f",
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
	{ID: "amazon-linux-extras@1.6.7-1.amzn2.noarch", Name: "amazon-linux-extras", Version: "1.6.7", Release: "1.amzn2", Arch: "noarch", SrcName: "amazon-linux-extras", SrcVersion: "1.6.7",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64", "system-release@2-10.amzn2.x86_64"}},
	{ID: "basesystem@10.0-7.amzn2.0.1.noarch", Name: "basesystem", Version: "10.0", Release: "7.amzn2.0.1", Arch: "noarch", SrcName: "basesystem", SrcVersion: "10.0",
		SrcRelease: "7.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"filesystem@3.2-25.amzn2.0.4.x86_64", "setup@2.8.71-10.amzn2.noarch"}},
	{ID: "bash@4.2.46-30.amzn2.x86_64", Name: "bash", Version: "4.2.46", Release: "30.amzn2", Arch: "x86_64", SrcName: "bash", SrcVersion: "4.2.46",
		SrcRelease: "30.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", Name: "bzip2-libs", Version: "1.0.6", Release: "13.amzn2.0.2", Arch: "x86_64", SrcName: "bzip2", SrcVersion: "1.0.6",
		SrcRelease: "13.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "ca-certificates@2018.2.22-70.0.amzn2.noarch", Name: "ca-certificates", Version: "2018.2.22", Release: "70.0.amzn2", Arch: "noarch", SrcName: "ca-certificates", SrcVersion: "2018.2.22",
		SrcRelease: "70.0.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "p11-kit-trust@0.23.5-3.amzn2.0.2.x86_64", "p11-kit@0.23.5-3.amzn2.0.2.x86_64"}},
	{ID: "chkconfig@1.7.4-1.amzn2.0.2.x86_64", Name: "chkconfig", Version: "1.7.4", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "chkconfig", SrcVersion: "1.7.4",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "libsepol@2.5-8.1.amzn2.0.2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64"}},
	{ID: "coreutils@8.22-21.amzn2.x86_64", Name: "coreutils", Version: "8.22", Release: "21.amzn2", Arch: "x86_64", SrcName: "coreutils", SrcVersion: "8.22",
		SrcRelease: "21.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "gmp@6.0.0-15.amzn2.0.2.x86_64", "grep@2.20-3.amzn2.0.2.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libattr@2.4.46-12.amzn2.0.2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "ncurses@6.0-8.20170212.amzn2.1.2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64"}},
	{ID: "cpio@2.11-27.amzn2.x86_64", Name: "cpio", Version: "2.11", Release: "27.amzn2", Arch: "x86_64", SrcName: "cpio", SrcVersion: "2.11",
		SrcRelease: "27.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "curl@7.61.1-9.amzn2.0.1.x86_64", Name: "curl", Version: "7.61.1", Release: "9.amzn2.0.1", Arch: "x86_64", SrcName: "curl", SrcVersion: "7.61.1",
		SrcRelease: "9.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libcurl@7.61.1-9.amzn2.0.1.x86_64", "libmetalink@0.1.2-7.amzn2.0.2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "cyrus-sasl-lib@2.1.26-23.amzn2.x86_64", Name: "cyrus-sasl-lib", Version: "2.1.26", Release: "23.amzn2", Arch: "x86_64", SrcName: "cyrus-sasl", SrcVersion: "2.1.26",
		SrcRelease: "23.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD with advertising"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "krb5-libs@1.15.1-20.amzn2.0.1.x86_64", "libcom_err@1.42.9-12.amzn2.0.2.x86_64", "libcrypt@2.26-32.amzn2.0.1.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64"}},
	{ID: "diffutils@3.3-4.amzn2.0.2.x86_64", Name: "diffutils", Version: "3.3", Release: "4.amzn2.0.2", Arch: "x86_64", SrcName: "diffutils", SrcVersion: "3.3",
		SrcRelease: "4.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "info@5.1-5.amzn2.x86_64"}},
	{ID: "elfutils-libelf@0.170-4.amzn2.x86_64", Name: "elfutils-libelf", Version: "0.170", Release: "4.amzn2", Arch: "x86_64", SrcName: "elfutils", SrcVersion: "0.170",
		SrcRelease: "4.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+ or LGPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "expat@2.1.0-10.amzn2.0.2.x86_64", Name: "expat", Version: "2.1.0", Release: "10.amzn2.0.2", Arch: "x86_64", SrcName: "expat", SrcVersion: "2.1.0",
		SrcRelease: "10.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "file-libs@5.11-33.amzn2.0.2.x86_64", Name: "file-libs", Version: "5.11", Release: "33.amzn2.0.2", Arch: "x86_64", SrcName: "file", SrcVersion: "5.11",
		SrcRelease: "33.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "filesystem@3.2-25.amzn2.0.4.x86_64", Name: "filesystem", Version: "3.2", Release: "25.amzn2.0.4", Arch: "x86_64", SrcName: "filesystem", SrcVersion: "3.2",
		SrcRelease: "25.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "setup@2.8.71-10.amzn2.noarch"}},
	{ID: "findutils@4.5.11-5.amzn2.0.2.x86_64", Name: "findutils", Version: "4.5.11", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "findutils", SrcVersion: "4.5.11",
		SrcRelease: "5.amzn2.0.2", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64"}},
	{ID: "gawk@4.0.2-4.amzn2.1.2.x86_64", Name: "gawk", Version: "4.0.2", Release: "4.amzn2.1.2", Arch: "x86_64", SrcName: "gawk", SrcVersion: "4.0.2",
		SrcRelease: "4.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+ and GPL and LGPLv3+ and LGPL and BSD"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "gdbm@1.13-6.amzn2.0.2.x86_64", Name: "gdbm", Version: "1.13", Release: "6.amzn2.0.2", Arch: "x86_64", SrcName: "gdbm", SrcVersion: "1.13",
		SrcRelease: "6.amzn2.0.2", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "readline@6.2-10.amzn2.0.2.x86_64"}},
	{ID: "glib2@2.54.2-2.amzn2.x86_64", Name: "glib2", Version: "2.54.2", Release: "2.amzn2", Arch: "x86_64", SrcName: "glib2", SrcVersion: "2.54.2",
		SrcRelease: "2.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libffi@3.0.13-18.amzn2.0.2.x86_64", "libgcc@7.3.1-5.amzn2.0.2.x86_64", "libmount@2.30.2-2.amzn2.0.4.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "pcre@8.32-17.amzn2.0.2.x86_64", "shared-mime-info@1.8-4.amzn2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "glibc@2.26-32.amzn2.0.1.x86_64", Name: "glibc", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"basesystem@10.0-7.amzn2.0.1.noarch", "glibc-common@2.26-32.amzn2.0.1.x86_64", "glibc-minimal-langpack@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "glibc-common@2.26-32.amzn2.0.1.x86_64", Name: "glibc-common", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "tzdata@2018i-1.amzn2.noarch"}},
	{ID: "glibc-langpack-en@2.26-32.amzn2.0.1.x86_64", Name: "glibc-langpack-en", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"glibc-common@2.26-32.amzn2.0.1.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "glibc-minimal-langpack@2.26-32.amzn2.0.1.x86_64", Name: "glibc-minimal-langpack", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"glibc-common@2.26-32.amzn2.0.1.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "gmp@6.0.0-15.amzn2.0.2.x86_64", Name: "gmp", Version: "6.0.0", Release: "15.amzn2.0.2", Arch: "x86_64", SrcName: "gmp", SrcVersion: "6.0.0",
		SrcRelease: "15.amzn2.0.2", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv3+ or GPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgcc@7.3.1-5.amzn2.0.2.x86_64", "libstdc++@7.3.1-5.amzn2.0.2.x86_64"}},
	{ID: "gnupg2@2.0.22-5.amzn2.0.3.x86_64", Name: "gnupg2", Version: "2.0.22", Release: "5.amzn2.0.3", Arch: "x86_64", SrcName: "gnupg2", SrcVersion: "2.0.22",
		SrcRelease: "5.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libassuan@2.1.0-3.amzn2.0.2.x86_64", "libcurl@7.61.1-9.amzn2.0.1.x86_64", "libgcrypt@1.5.3-14.amzn2.0.2.x86_64", "libgpg-error@1.12-3.amzn2.0.3.x86_64", "openldap@2.4.44-15.amzn2.x86_64", "pinentry@0.8.1-17.amzn2.0.2.x86_64", "pth@2.0.7-23.amzn2.0.2.x86_64", "readline@6.2-10.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "gpg-pubkey@c87f5b1a-593863f8.", Name: "gpg-pubkey", Version: "c87f5b1a", Release: "593863f8", Arch: "None", SrcName: "", SrcVersion: "",
		SrcRelease: "", Epoch: 0, SrcEpoch: 0, Maintainer: "", Layer: types.Layer{}, Licenses: []string{"pubkey"}},
	{ID: "gpgme@1.3.2-5.amzn2.0.2.x86_64", Name: "gpgme", Version: "1.3.2", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "gpgme", SrcVersion: "1.3.2",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "gnupg2@2.0.22-5.amzn2.0.3.x86_64", "libassuan@2.1.0-3.amzn2.0.2.x86_64", "libgpg-error@1.12-3.amzn2.0.3.x86_64"}},
	{ID: "grep@2.20-3.amzn2.0.2.x86_64", Name: "grep", Version: "2.20", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "grep", SrcVersion: "2.20",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "pcre@8.32-17.amzn2.0.2.x86_64"}},
	{ID: "info@5.1-5.amzn2.x86_64", Name: "info", Version: "5.1", Release: "5.amzn2", Arch: "x86_64", SrcName: "texinfo", SrcVersion: "5.1",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "keyutils-libs@1.5.8-3.amzn2.0.2.x86_64", Name: "keyutils-libs", Version: "1.5.8", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "keyutils", SrcVersion: "1.5.8",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+ and LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "krb5-libs@1.15.1-20.amzn2.0.1.x86_64", Name: "krb5-libs", Version: "1.15.1", Release: "20.amzn2.0.1", Arch: "x86_64", SrcName: "krb5", SrcVersion: "1.15.1",
		SrcRelease: "20.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "gawk@4.0.2-4.amzn2.1.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "grep@2.20-3.amzn2.0.2.x86_64", "keyutils-libs@1.5.8-3.amzn2.0.2.x86_64", "libcom_err@1.42.9-12.amzn2.0.2.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "libverto@0.2.5-4.amzn2.0.2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "sed@4.2.2-5.amzn2.0.2.x86_64"}},
	{ID: "libacl@2.2.51-14.amzn2.x86_64", Name: "libacl", Version: "2.2.51", Release: "14.amzn2", Arch: "x86_64", SrcName: "acl", SrcVersion: "2.2.51",
		SrcRelease: "14.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libattr@2.4.46-12.amzn2.0.2.x86_64"}},
	{ID: "libassuan@2.1.0-3.amzn2.0.2.x86_64", Name: "libassuan", Version: "2.1.0", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "libassuan", SrcVersion: "2.1.0",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and GPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgpg-error@1.12-3.amzn2.0.3.x86_64"}},
	{ID: "libattr@2.4.46-12.amzn2.0.2.x86_64", Name: "libattr", Version: "2.4.46", Release: "12.amzn2.0.2", Arch: "x86_64", SrcName: "attr", SrcVersion: "2.4.46",
		SrcRelease: "12.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libblkid@2.30.2-2.amzn2.0.4.x86_64", Name: "libblkid", Version: "2.30.2", Release: "2.amzn2.0.4", Arch: "x86_64", SrcName: "util-linux", SrcVersion: "2.30.2",
		SrcRelease: "2.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libuuid@2.30.2-2.amzn2.0.4.x86_64"}},
	{ID: "libcap@2.22-9.amzn2.0.2.x86_64", Name: "libcap", Version: "2.22", Release: "9.amzn2.0.2", Arch: "x86_64", SrcName: "libcap", SrcVersion: "2.22",
		SrcRelease: "9.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libattr@2.4.46-12.amzn2.0.2.x86_64"}},
	{ID: "libcom_err@1.42.9-12.amzn2.0.2.x86_64", Name: "libcom_err", Version: "1.42.9", Release: "12.amzn2.0.2", Arch: "x86_64", SrcName: "e2fsprogs", SrcVersion: "1.42.9",
		SrcRelease: "12.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libcrypt@2.26-32.amzn2.0.1.x86_64", Name: "libcrypt", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libcurl@7.61.1-9.amzn2.0.1.x86_64", Name: "libcurl", Version: "7.61.1", Release: "9.amzn2.0.1", Arch: "x86_64", SrcName: "curl", SrcVersion: "7.61.1",
		SrcRelease: "9.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "krb5-libs@1.15.1-20.amzn2.0.1.x86_64", "libcom_err@1.42.9-12.amzn2.0.2.x86_64", "libidn2@2.0.4-1.amzn2.0.2.x86_64", "libnghttp2@1.31.1-1.amzn2.0.2.x86_64", "libssh2@1.4.3-12.amzn2.2.x86_64", "nss-pem@1.0.3-5.amzn2.x86_64", "openldap@2.4.44-15.amzn2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "libdb@5.3.21-24.amzn2.0.3.x86_64", Name: "libdb", Version: "5.3.21", Release: "24.amzn2.0.3", Arch: "x86_64", SrcName: "libdb", SrcVersion: "5.3.21",
		SrcRelease: "24.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD and LGPLv2 and Sleepycat"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libdb-utils@5.3.21-24.amzn2.0.3.x86_64", Name: "libdb-utils", Version: "5.3.21", Release: "24.amzn2.0.3", Arch: "x86_64", SrcName: "libdb", SrcVersion: "5.3.21",
		SrcRelease: "24.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD and LGPLv2 and Sleepycat"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64"}},
	{ID: "libffi@3.0.13-18.amzn2.0.2.x86_64", Name: "libffi", Version: "3.0.13", Release: "18.amzn2.0.2", Arch: "x86_64", SrcName: "libffi", SrcVersion: "3.0.13",
		SrcRelease: "18.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT and Public Domain"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libgcc@7.3.1-5.amzn2.0.2.x86_64", Name: "libgcc", Version: "7.3.1", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "gcc", SrcVersion: "7.3.1",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libgcrypt@1.5.3-14.amzn2.0.2.x86_64", Name: "libgcrypt", Version: "1.5.3", Release: "14.amzn2.0.2", Arch: "x86_64", SrcName: "libgcrypt", SrcVersion: "1.5.3",
		SrcRelease: "14.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgpg-error@1.12-3.amzn2.0.3.x86_64"}},
	{ID: "libgpg-error@1.12-3.amzn2.0.3.x86_64", Name: "libgpg-error", Version: "1.12", Release: "3.amzn2.0.3", Arch: "x86_64", SrcName: "libgpg-error", SrcVersion: "1.12",
		SrcRelease: "3.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libidn2@2.0.4-1.amzn2.0.2.x86_64", Name: "libidn2", Version: "2.0.4", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "libidn2", SrcVersion: "2.0.4",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"(GPLv2+ or LGPLv3+) and GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libunistring@0.9.3-9.amzn2.0.2.x86_64"}},
	{ID: "libmetalink@0.1.2-7.amzn2.0.2.x86_64", Name: "libmetalink", Version: "0.1.2", Release: "7.amzn2.0.2", Arch: "x86_64", SrcName: "libmetalink", SrcVersion: "0.1.2",
		SrcRelease: "7.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"expat@2.1.0-10.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libmount@2.30.2-2.amzn2.0.4.x86_64", Name: "libmount", Version: "2.30.2", Release: "2.amzn2.0.4", Arch: "x86_64", SrcName: "util-linux", SrcVersion: "2.30.2",
		SrcRelease: "2.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libblkid@2.30.2-2.amzn2.0.4.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "libuuid@2.30.2-2.amzn2.0.4.x86_64"}},
	{ID: "libnghttp2@1.31.1-1.amzn2.0.2.x86_64", Name: "libnghttp2", Version: "1.31.1", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "nghttp2", SrcVersion: "1.31.1",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libselinux@2.5-12.amzn2.0.2.x86_64", Name: "libselinux", Version: "2.5", Release: "12.amzn2.0.2", Arch: "x86_64", SrcName: "libselinux", SrcVersion: "2.5",
		SrcRelease: "12.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libsepol@2.5-8.1.amzn2.0.2.x86_64", "pcre@8.32-17.amzn2.0.2.x86_64"}},
	{ID: "libsepol@2.5-8.1.amzn2.0.2.x86_64", Name: "libsepol", Version: "2.5", Release: "8.1.amzn2.0.2", Arch: "x86_64", SrcName: "libsepol", SrcVersion: "2.5",
		SrcRelease: "8.1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libssh2@1.4.3-12.amzn2.2.x86_64", Name: "libssh2", Version: "1.4.3", Release: "12.amzn2.2", Arch: "x86_64", SrcName: "libssh2", SrcVersion: "1.4.3",
		SrcRelease: "12.amzn2.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "libstdc++@7.3.1-5.amzn2.0.2.x86_64", Name: "libstdc++", Version: "7.3.1", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "gcc", SrcVersion: "7.3.1",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgcc@7.3.1-5.amzn2.0.2.x86_64"}},
	{ID: "libtasn1@4.10-1.amzn2.0.2.x86_64", Name: "libtasn1", Version: "4.10", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "libtasn1", SrcVersion: "4.10",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+ and LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libunistring@0.9.3-9.amzn2.0.2.x86_64", Name: "libunistring", Version: "0.9.3", Release: "9.amzn2.0.2", Arch: "x86_64", SrcName: "libunistring", SrcVersion: "0.9.3",
		SrcRelease: "9.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "info@5.1-5.amzn2.x86_64"}},
	{ID: "libuuid@2.30.2-2.amzn2.0.4.x86_64", Name: "libuuid", Version: "2.30.2", Release: "2.amzn2.0.4", Arch: "x86_64", SrcName: "util-linux", SrcVersion: "2.30.2",
		SrcRelease: "2.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libverto@0.2.5-4.amzn2.0.2.x86_64", Name: "libverto", Version: "0.2.5", Release: "4.amzn2.0.2", Arch: "x86_64", SrcName: "libverto", SrcVersion: "0.2.5",
		SrcRelease: "4.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "libxml2@2.9.1-6.amzn2.3.2.x86_64", Name: "libxml2", Version: "2.9.1", Release: "6.amzn2.3.2", Arch: "x86_64", SrcName: "libxml2", SrcVersion: "2.9.1",
		SrcRelease: "6.amzn2.3.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "lua@5.1.4-15.amzn2.0.2.x86_64", Name: "lua", Version: "5.1.4", Release: "15.amzn2.0.2", Arch: "x86_64", SrcName: "lua", SrcVersion: "5.1.4",
		SrcRelease: "15.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "readline@6.2-10.amzn2.0.2.x86_64"}},
	{ID: "ncurses@6.0-8.20170212.amzn2.1.2.x86_64", Name: "ncurses", Version: "6.0", Release: "8.20170212.amzn2.1.2", Arch: "x86_64", SrcName: "ncurses", SrcVersion: "6.0",
		SrcRelease: "8.20170212.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "ncurses-base@6.0-8.20170212.amzn2.1.2.noarch", Name: "ncurses-base", Version: "6.0", Release: "8.20170212.amzn2.1.2", Arch: "noarch", SrcName: "ncurses", SrcVersion: "6.0",
		SrcRelease: "8.20170212.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{ID: "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", Name: "ncurses-libs", Version: "6.0", Release: "8.20170212.amzn2.1.2", Arch: "x86_64", SrcName: "ncurses", SrcVersion: "6.0",
		SrcRelease: "8.20170212.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-base@6.0-8.20170212.amzn2.1.2.noarch"}},
	{ID: "nspr@4.19.0-1.amzn2.x86_64", Name: "nspr", Version: "4.19.0", Release: "1.amzn2", Arch: "x86_64", SrcName: "nspr", SrcVersion: "4.19.0",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "nss@3.36.0-7.amzn2.x86_64", Name: "nss", Version: "3.36.0", Release: "7.amzn2", Arch: "x86_64", SrcName: "nss", SrcVersion: "3.36.0",
		SrcRelease: "7.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-pem@1.0.3-5.amzn2.x86_64", "nss-softokn@3.36.0-5.amzn2.x86_64", "nss-sysinit@3.36.0-7.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64"}},
	{ID: "nss-pem@1.0.3-5.amzn2.x86_64", Name: "nss-pem", Version: "1.0.3", Release: "5.amzn2", Arch: "x86_64", SrcName: "nss-pem", SrcVersion: "1.0.3",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv1.1"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "nss@3.36.0-7.amzn2.x86_64"}},
	{ID: "nss-softokn@3.36.0-5.amzn2.x86_64", Name: "nss-softokn", Version: "3.36.0", Release: "5.amzn2", Arch: "x86_64", SrcName: "nss-softokn", SrcVersion: "3.36.0",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-softokn-freebl@3.36.0-5.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "sqlite@3.7.17-8.amzn2.0.2.x86_64"}},
	{ID: "nss-softokn-freebl@3.36.0-5.amzn2.x86_64", Name: "nss-softokn-freebl", Version: "3.36.0", Release: "5.amzn2", Arch: "x86_64", SrcName: "nss-softokn", SrcVersion: "3.36.0",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64"}},
	{ID: "nss-sysinit@3.36.0-7.amzn2.x86_64", Name: "nss-sysinit", Version: "3.36.0", Release: "7.amzn2", Arch: "x86_64", SrcName: "nss", SrcVersion: "3.36.0",
		SrcRelease: "7.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "sed@4.2.2-5.amzn2.0.2.x86_64"}},
	{ID: "nss-tools@3.36.0-7.amzn2.x86_64", Name: "nss-tools", Version: "3.36.0", Release: "7.amzn2", Arch: "x86_64", SrcName: "nss", SrcVersion: "3.36.0",
		SrcRelease: "7.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-softokn@3.36.0-5.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "nss-util@3.36.0-1.amzn2.x86_64", Name: "nss-util", Version: "3.36.0", Release: "1.amzn2", Arch: "x86_64", SrcName: "nss-util", SrcVersion: "3.36.0",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64"}},
	{ID: "openldap@2.4.44-15.amzn2.x86_64", Name: "openldap", Version: "2.4.44", Release: "15.amzn2", Arch: "x86_64", SrcName: "openldap", SrcVersion: "2.4.44",
		SrcRelease: "15.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"OpenLDAP"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "cyrus-sasl-lib@2.1.26-23.amzn2.x86_64", "findutils@4.5.11-5.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "nspr@4.19.0-1.amzn2.x86_64", "nss-tools@3.36.0-7.amzn2.x86_64", "nss-util@3.36.0-1.amzn2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "rpm@4.11.3-25.amzn2.0.3.x86_64"}},
	{ID: "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", Name: "openssl-libs", Version: "1.0.2k", Release: "16.amzn2.1.1", Arch: "x86_64", SrcName: "openssl", SrcVersion: "1.0.2k",
		SrcRelease: "16.amzn2.1.1", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"OpenSSL"}, DependsOn: []string{"ca-certificates@2018.2.22-70.0.amzn2.noarch", "glibc@2.26-32.amzn2.0.1.x86_64", "krb5-libs@1.15.1-20.amzn2.0.1.x86_64", "libcom_err@1.42.9-12.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "p11-kit@0.23.5-3.amzn2.0.2.x86_64", Name: "p11-kit", Version: "0.23.5", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "p11-kit", SrcVersion: "0.23.5",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libffi@3.0.13-18.amzn2.0.2.x86_64"}},
	{ID: "p11-kit-trust@0.23.5-3.amzn2.0.2.x86_64", Name: "p11-kit-trust", Version: "0.23.5", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "p11-kit", SrcVersion: "0.23.5",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libffi@3.0.13-18.amzn2.0.2.x86_64", "libtasn1@4.10-1.amzn2.0.2.x86_64", "nss-softokn-freebl@3.36.0-5.amzn2.x86_64", "p11-kit@0.23.5-3.amzn2.0.2.x86_64"}},
	{ID: "pcre@8.32-17.amzn2.0.2.x86_64", Name: "pcre", Version: "8.32", Release: "17.amzn2.0.2", Arch: "x86_64", SrcName: "pcre", SrcVersion: "8.32",
		SrcRelease: "17.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"BSD"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libgcc@7.3.1-5.amzn2.0.2.x86_64", "libstdc++@7.3.1-5.amzn2.0.2.x86_64"}},
	{ID: "pinentry@0.8.1-17.amzn2.0.2.x86_64", Name: "pinentry", Version: "0.8.1", Release: "17.amzn2.0.2", Arch: "x86_64", SrcName: "pinentry", SrcVersion: "0.8.1",
		SrcRelease: "17.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "popt@1.13-16.amzn2.0.2.x86_64", Name: "popt", Version: "1.13", Release: "16.amzn2.0.2", Arch: "x86_64", SrcName: "popt", SrcVersion: "1.13",
		SrcRelease: "16.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "pth@2.0.7-23.amzn2.0.2.x86_64", Name: "pth", Version: "2.0.7", Release: "23.amzn2.0.2", Arch: "x86_64", SrcName: "pth", SrcVersion: "2.0.7",
		SrcRelease: "23.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "pygpgme@0.3-9.amzn2.0.2.x86_64", Name: "pygpgme", Version: "0.3", Release: "9.amzn2.0.2", Arch: "x86_64", SrcName: "pygpgme", SrcVersion: "0.3",
		SrcRelease: "9.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "gpgme@1.3.2-5.amzn2.0.2.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "pyliblzma@0.5.3-11.amzn2.0.2.x86_64", Name: "pyliblzma", Version: "0.5.3", Release: "11.amzn2.0.2", Arch: "x86_64", SrcName: "pyliblzma", SrcVersion: "0.5.3",
		SrcRelease: "11.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv3+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64"}},
	{ID: "python@2.7.14-58.amzn2.0.4.x86_64", Name: "python", Version: "2.7.14", Release: "58.amzn2.0.4", Arch: "x86_64", SrcName: "python", SrcVersion: "2.7.14",
		SrcRelease: "58.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Python"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "python-iniparse@0.4-9.amzn2.noarch", Name: "python-iniparse", Version: "0.4", Release: "9.amzn2", Arch: "noarch", SrcName: "python-iniparse", SrcVersion: "0.4",
		SrcRelease: "9.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"MIT"}, DependsOn: []string{"python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "python-libs@2.7.14-58.amzn2.0.4.x86_64", Name: "python-libs", Version: "2.7.14", Release: "58.amzn2.0.4", Arch: "x86_64", SrcName: "python", SrcVersion: "2.7.14",
		SrcRelease: "58.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Python"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "expat@2.1.0-10.amzn2.0.2.x86_64", "gdbm@1.13-6.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libcrypt@2.26-32.amzn2.0.1.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libffi@3.0.13-18.amzn2.0.2.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "openssl-libs@1.0.2k-16.amzn2.1.1.x86_64", "readline@6.2-10.amzn2.0.2.x86_64", "sqlite@3.7.17-8.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "python-pycurl@7.19.0-19.amzn2.0.2.x86_64", Name: "python-pycurl", Version: "7.19.0", Release: "19.amzn2.0.2", Arch: "x86_64", SrcName: "python-pycurl", SrcVersion: "7.19.0",
		SrcRelease: "19.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+ or MIT"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "keyutils-libs@1.5.8-3.amzn2.0.2.x86_64", "libcurl@7.61.1-9.amzn2.0.1.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "python-urlgrabber@3.10-8.amzn2.noarch", Name: "python-urlgrabber", Version: "3.10", Release: "8.amzn2", Arch: "noarch", SrcName: "python-urlgrabber", SrcVersion: "3.10",
		SrcRelease: "8.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"python-pycurl@7.19.0-19.amzn2.0.2.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "pyxattr@0.5.1-5.amzn2.0.2.x86_64", Name: "pyxattr", Version: "0.5.1", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "pyxattr", SrcVersion: "0.5.1",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libattr@2.4.46-12.amzn2.0.2.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64"}},
	{ID: "readline@6.2-10.amzn2.0.2.x86_64", Name: "readline", Version: "6.2", Release: "10.amzn2.0.2", Arch: "x86_64", SrcName: "readline", SrcVersion: "6.2",
		SrcRelease: "10.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "rpm@4.11.3-25.amzn2.0.3.x86_64", Name: "rpm", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "curl@7.61.1-9.amzn2.0.1.x86_64", "elfutils-libelf@0.170-4.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "lua@5.1.4-15.amzn2.0.2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64", "rpm-libs@4.11.3-25.amzn2.0.3.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "rpm-build-libs@4.11.3-25.amzn2.0.3.x86_64", Name: "rpm-build-libs", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+ and LGPLv2+ with exceptions"}, DependsOn: []string{"bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "elfutils-libelf@0.170-4.amzn2.x86_64", "file-libs@5.11-33.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "lua@5.1.4-15.amzn2.0.2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64", "rpm-libs@4.11.3-25.amzn2.0.3.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "rpm-libs@4.11.3-25.amzn2.0.3.x86_64", Name: "rpm-libs", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+ and LGPLv2+ with exceptions"}, DependsOn: []string{"bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "elfutils-libelf@0.170-4.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "lua@5.1.4-15.amzn2.0.2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64", "rpm@4.11.3-25.amzn2.0.3.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "rpm-python@4.11.3-25.amzn2.0.3.x86_64", Name: "rpm-python", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"bzip2-libs@1.0.6-13.amzn2.0.2.x86_64", "elfutils-libelf@0.170-4.amzn2.x86_64", "file-libs@5.11-33.amzn2.0.2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libcap@2.22-9.amzn2.0.2.x86_64", "libdb@5.3.21-24.amzn2.0.3.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "lua@5.1.4-15.amzn2.0.2.x86_64", "nss@3.36.0-7.amzn2.x86_64", "popt@1.13-16.amzn2.0.2.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64", "rpm-build-libs@4.11.3-25.amzn2.0.3.x86_64", "rpm-libs@4.11.3-25.amzn2.0.3.x86_64", "rpm@4.11.3-25.amzn2.0.3.x86_64", "xz-libs@5.2.2-1.amzn2.0.2.x86_64", "zlib@1.2.7-17.amzn2.0.2.x86_64"}},
	{ID: "sed@4.2.2-5.amzn2.0.2.x86_64", Name: "sed", Version: "4.2.2", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "sed", SrcVersion: "4.2.2",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv3+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64"}},
	{ID: "setup@2.8.71-10.amzn2.noarch", Name: "setup", Version: "2.8.71", Release: "10.amzn2", Arch: "noarch", SrcName: "setup", SrcVersion: "2.8.71",
		SrcRelease: "10.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"system-release@2-10.amzn2.x86_64"}},
	{ID: "shared-mime-info@1.8-4.amzn2.x86_64", Name: "shared-mime-info", Version: "1.8", Release: "4.amzn2", Arch: "x86_64", SrcName: "shared-mime-info", SrcVersion: "1.8",
		SrcRelease: "4.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64", "coreutils@8.22-21.amzn2.x86_64", "glib2@2.54.2-2.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libxml2@2.9.1-6.amzn2.3.2.x86_64"}},
	{ID: "sqlite@3.7.17-8.amzn2.0.2.x86_64", Name: "sqlite", Version: "3.7.17", Release: "8.amzn2.0.2", Arch: "x86_64", SrcName: "sqlite", SrcVersion: "3.7.17",
		SrcRelease: "8.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64", "readline@6.2-10.amzn2.0.2.x86_64"}},
	{ID: "system-release@2-10.amzn2.x86_64", Name: "system-release", Version: "2", Release: "10.amzn2", Arch: "x86_64", SrcName: "system-release", SrcVersion: "2",
		SrcRelease: "10.amzn2", Epoch: 1, SrcEpoch: 1, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2"}, DependsOn: []string{"bash@4.2.46-30.amzn2.x86_64"}},
	{ID: "tzdata@2018i-1.amzn2.noarch", Name: "tzdata", Version: "2018i", Release: "1.amzn2", Arch: "noarch", SrcName: "tzdata", SrcVersion: "2018i",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Public Domain"}},
	{ID: "vim-minimal@7.4.160-4.amzn2.0.16.x86_64", Name: "vim-minimal", Version: "7.4.160", Release: "4.amzn2.0.16", Arch: "x86_64", SrcName: "vim", SrcVersion: "7.4.160",
		SrcRelease: "4.amzn2.0.16", Epoch: 2, SrcEpoch: 2, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"Vim"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64", "libacl@2.2.51-14.amzn2.x86_64", "libselinux@2.5-12.amzn2.0.2.x86_64", "ncurses-libs@6.0-8.20170212.amzn2.1.2.x86_64"}},
	{ID: "xz-libs@5.2.2-1.amzn2.0.2.x86_64", Name: "xz-libs", Version: "5.2.2", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "xz", SrcVersion: "5.2.2",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
	{ID: "yum@3.4.3-158.amzn2.0.2.noarch", Name: "yum", Version: "3.4.3", Release: "158.amzn2.0.2", Arch: "noarch", SrcName: "yum", SrcVersion: "3.4.3",
		SrcRelease: "158.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"cpio@2.11-27.amzn2.x86_64", "diffutils@3.3-4.amzn2.0.2.x86_64", "pygpgme@0.3-9.amzn2.0.2.x86_64", "pyliblzma@0.5.3-11.amzn2.0.2.x86_64", "python-iniparse@0.4-9.amzn2.noarch", "python-urlgrabber@3.10-8.amzn2.noarch", "python@2.7.14-58.amzn2.0.4.x86_64", "pyxattr@0.5.1-5.amzn2.0.2.x86_64", "rpm-python@4.11.3-25.amzn2.0.3.x86_64", "rpm@4.11.3-25.amzn2.0.3.x86_64", "yum-metadata-parser@1.1.4-10.amzn2.0.2.x86_64"}},
	{ID: "yum-metadata-parser@1.1.4-10.amzn2.0.2.x86_64", Name: "yum-metadata-parser", Version: "1.1.4", Release: "10.amzn2.0.2", Arch: "x86_64", SrcName: "yum-metadata-parser", SrcVersion: "1.1.4",
		SrcRelease: "10.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2"}, DependsOn: []string{"glib2@2.54.2-2.amzn2.x86_64", "glibc@2.26-32.amzn2.0.1.x86_64", "libxml2@2.9.1-6.amzn2.3.2.x86_64", "python-libs@2.7.14-58.amzn2.0.4.x86_64", "python@2.7.14-58.amzn2.0.4.x86_64", "sqlite@3.7.17-8.amzn2.0.2.x86_64"}},
	{ID: "yum-plugin-ovl@1.1.31-46.amzn2.0.1.noarch", Name: "yum-plugin-ovl", Version: "1.1.31", Release: "46.amzn2.0.1", Arch: "noarch", SrcName: "yum-utils", SrcVersion: "1.1.31",
		SrcRelease: "46.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"yum@3.4.3-158.amzn2.0.2.noarch"}},
	{ID: "yum-plugin-priorities@1.1.31-46.amzn2.0.1.noarch", Name: "yum-plugin-priorities", Version: "1.1.31", Release: "46.amzn2.0.1", Arch: "noarch", SrcName: "yum-utils", SrcVersion: "1.1.31",
		SrcRelease: "46.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"GPLv2+"}, DependsOn: []string{"yum@3.4.3-158.amzn2.0.2.noarch"}},
	{ID: "zlib@1.2.7-17.amzn2.0.2.x86_64", Name: "zlib", Version: "1.2.7", Release: "17.amzn2.0.2", Arch: "x86_64", SrcName: "zlib", SrcVersion: "1.2.7",
		SrcRelease: "17.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Maintainer: "Amazon Linux", Layer: types.Layer{}, Licenses: []string{"zlib and Boost"}, DependsOn: []string{"glibc@2.26-32.amzn2.0.1.x86_64"}},
}
