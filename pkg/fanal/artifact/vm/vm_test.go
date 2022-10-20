package vm

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/all"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/storage"
)

var m storage.Storage = &MockStorage{}

type MockStorage struct {
	*os.File
}

func (m MockStorage) Open(s string, _ context.Context) (sr *io.SectionReader, cacheKey string, err error) {
	t := strings.TrimPrefix(s, storage.EBSPrefix)
	fp, err := os.Open(t)
	if err != nil {
		return nil, "", err
	}
	m.File = fp
	fi, err := m.Stat()
	if err != nil {
		return nil, "", err
	}
	return io.NewSectionReader(m, 0, fi.Size()), s, nil
}

func (m MockStorage) Close() error {
	return m.File.Close()
}

func TestArtifact_Inspect(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name                    string
		fields                  fields
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
			name: "happy path for raw image",
			fields: fields{
				dir: "testdata/AmazonLinux2.img",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:01d627752e149d7e35978e86c94c180dd5b5993dd8b5897de8dec328ac049a26",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: &types.OS{
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
						ArtifactID: "sha256:01d627752e149d7e35978e86c94c180dd5b5993dd8b5897de8dec328ac049a26",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
						},
					},
				},
			},

			want: types.ArtifactReference{
				Name: "testdata/AmazonLinux2.img",
				Type: types.ArtifactVM,
				ID:   "sha256:01d627752e149d7e35978e86c94c180dd5b5993dd8b5897de8dec328ac049a26",
				BlobIDs: []string{
					"sha256:01d627752e149d7e35978e86c94c180dd5b5993dd8b5897de8dec328ac049a26",
				},
			},
		},
		{
			name: "happy path for ebs",
			fields: fields{
				dir: "ebs:testdata/AmazonLinux2.img",
			},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "vm:ebs:testdata/AmazonLinux2.img",
					BlobIDs:    []string{"vm:ebs:testdata/AmazonLinux2.img"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "vm:ebs:testdata/AmazonLinux2.img",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: &types.OS{
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
						ArtifactID: "vm:ebs:testdata/AmazonLinux2.img",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "ebs:testdata/AmazonLinux2.img",
				Type: types.ArtifactVM,
				ID:   "vm:ebs:testdata/AmazonLinux2.img",
				BlobIDs: []string{
					"vm:ebs:testdata/AmazonLinux2.img",
				},
			},
		},
		{
			name: "sad path with no such directory",
			fields: fields{
				dir: "./testdata/unknown",
			},
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			c.ApplyMissingBlobsExpectation(tt.missingBlobsExpectation)
			c.ApplyPutArtifactExpectations(tt.putArtifactExpectations)

			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			// Patch Artifact.store for EBS
			if strings.HasPrefix(tt.fields.dir, storage.EBSPrefix) {
				va := a.(Artifact)
				va.store = MockStorage{}
				a = va
			}

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
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
	{Name: "amazon-linux-extras", Version: "1.6.7", Release: "1.amzn2", Arch: "noarch", SrcName: "amazon-linux-extras", SrcVersion: "1.6.7",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2"}},
	{Name: "basesystem", Version: "10.0", Release: "7.amzn2.0.1", Arch: "noarch", SrcName: "basesystem", SrcVersion: "10.0",
		SrcRelease: "7.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"Public Domain"}},
	{Name: "bash", Version: "4.2.46", Release: "30.amzn2", Arch: "x86_64", SrcName: "bash", SrcVersion: "4.2.46",
		SrcRelease: "30.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "bzip2-libs", Version: "1.0.6", Release: "13.amzn2.0.2", Arch: "x86_64", SrcName: "bzip2", SrcVersion: "1.0.6",
		SrcRelease: "13.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD"}},
	{Name: "ca-certificates", Version: "2018.2.22", Release: "70.0.amzn2", Arch: "noarch", SrcName: "ca-certificates", SrcVersion: "2018.2.22",
		SrcRelease: "70.0.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"Public Domain"}},
	{Name: "chkconfig", Version: "1.7.4", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "chkconfig", SrcVersion: "1.7.4",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2"}},
	{Name: "coreutils", Version: "8.22", Release: "21.amzn2", Arch: "x86_64", SrcName: "coreutils", SrcVersion: "8.22",
		SrcRelease: "21.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "cpio", Version: "2.11", Release: "27.amzn2", Arch: "x86_64", SrcName: "cpio", SrcVersion: "2.11",
		SrcRelease: "27.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "curl", Version: "7.61.1", Release: "9.amzn2.0.1", Arch: "x86_64", SrcName: "curl", SrcVersion: "7.61.1",
		SrcRelease: "9.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "cyrus-sasl-lib", Version: "2.1.26", Release: "23.amzn2", Arch: "x86_64", SrcName: "cyrus-sasl", SrcVersion: "2.1.26",
		SrcRelease: "23.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD with advertising"}},
	{Name: "diffutils", Version: "3.3", Release: "4.amzn2.0.2", Arch: "x86_64", SrcName: "diffutils", SrcVersion: "3.3",
		SrcRelease: "4.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "elfutils-libelf", Version: "0.170", Release: "4.amzn2", Arch: "x86_64", SrcName: "elfutils", SrcVersion: "0.170",
		SrcRelease: "4.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+ or LGPLv3+"}},
	{Name: "expat", Version: "2.1.0", Release: "10.amzn2.0.2", Arch: "x86_64", SrcName: "expat", SrcVersion: "2.1.0",
		SrcRelease: "10.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "file-libs", Version: "5.11", Release: "33.amzn2.0.2", Arch: "x86_64", SrcName: "file", SrcVersion: "5.11",
		SrcRelease: "33.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD"}},
	{Name: "filesystem", Version: "3.2", Release: "25.amzn2.0.4", Arch: "x86_64", SrcName: "filesystem", SrcVersion: "3.2",
		SrcRelease: "25.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"Public Domain"}},
	{Name: "findutils", Version: "4.5.11", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "findutils", SrcVersion: "4.5.11",
		SrcRelease: "5.amzn2.0.2", Epoch: 1, SrcEpoch: 1, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "gawk", Version: "4.0.2", Release: "4.amzn2.1.2", Arch: "x86_64", SrcName: "gawk", SrcVersion: "4.0.2",
		SrcRelease: "4.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+ and GPL and LGPLv3+ and LGPL and BSD"}},
	{Name: "gdbm", Version: "1.13", Release: "6.amzn2.0.2", Arch: "x86_64", SrcName: "gdbm", SrcVersion: "1.13",
		SrcRelease: "6.amzn2.0.2", Epoch: 1, SrcEpoch: 1, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "glib2", Version: "2.54.2", Release: "2.amzn2", Arch: "x86_64", SrcName: "glib2", SrcVersion: "2.54.2",
		SrcRelease: "2.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "glibc", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}},
	{Name: "glibc-common", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}},
	{Name: "glibc-langpack-en", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}},
	{Name: "glibc-minimal-langpack", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}},
	{Name: "gmp", Version: "6.0.0", Release: "15.amzn2.0.2", Arch: "x86_64", SrcName: "gmp", SrcVersion: "6.0.0",
		SrcRelease: "15.amzn2.0.2", Epoch: 1, SrcEpoch: 1, Layer: types.Layer{}, Licenses: []string{"LGPLv3+ or GPLv2+"}},
	{Name: "gnupg2", Version: "2.0.22", Release: "5.amzn2.0.3", Arch: "x86_64", SrcName: "gnupg2", SrcVersion: "2.0.22",
		SrcRelease: "5.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "gpg-pubkey", Version: "c87f5b1a", Release: "593863f8", Arch: "None", SrcName: "", SrcVersion: "",
		SrcRelease: "", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"pubkey"}},
	{Name: "gpgme", Version: "1.3.2", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "gpgme", SrcVersion: "1.3.2",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "grep", Version: "2.20", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "grep", SrcVersion: "2.20",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "info", Version: "5.1", Release: "5.amzn2", Arch: "x86_64", SrcName: "texinfo", SrcVersion: "5.1",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "keyutils-libs", Version: "1.5.8", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "keyutils", SrcVersion: "1.5.8",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+ and LGPLv2+"}},
	{Name: "krb5-libs", Version: "1.15.1", Release: "20.amzn2.0.1", Arch: "x86_64", SrcName: "krb5", SrcVersion: "1.15.1",
		SrcRelease: "20.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "libacl", Version: "2.2.51", Release: "14.amzn2", Arch: "x86_64", SrcName: "acl", SrcVersion: "2.2.51",
		SrcRelease: "14.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "libassuan", Version: "2.1.0", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "libassuan", SrcVersion: "2.1.0",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and GPLv3+"}},
	{Name: "libattr", Version: "2.4.46", Release: "12.amzn2.0.2", Arch: "x86_64", SrcName: "attr", SrcVersion: "2.4.46",
		SrcRelease: "12.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "libblkid", Version: "2.30.2", Release: "2.amzn2.0.4", Arch: "x86_64", SrcName: "util-linux", SrcVersion: "2.30.2",
		SrcRelease: "2.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "libcap", Version: "2.22", Release: "9.amzn2.0.2", Arch: "x86_64", SrcName: "libcap", SrcVersion: "2.22",
		SrcRelease: "9.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "libcom_err", Version: "1.42.9", Release: "12.amzn2.0.2", Arch: "x86_64", SrcName: "e2fsprogs", SrcVersion: "1.42.9",
		SrcRelease: "12.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "libcrypt", Version: "2.26", Release: "32.amzn2.0.1", Arch: "x86_64", SrcName: "glibc", SrcVersion: "2.26",
		SrcRelease: "32.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+ and LGPLv2+ with exceptions and GPLv2+"}},
	{Name: "libcurl", Version: "7.61.1", Release: "9.amzn2.0.1", Arch: "x86_64", SrcName: "curl", SrcVersion: "7.61.1",
		SrcRelease: "9.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "libdb", Version: "5.3.21", Release: "24.amzn2.0.3", Arch: "x86_64", SrcName: "libdb", SrcVersion: "5.3.21",
		SrcRelease: "24.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD and LGPLv2 and Sleepycat"}},
	{Name: "libdb-utils", Version: "5.3.21", Release: "24.amzn2.0.3", Arch: "x86_64", SrcName: "libdb", SrcVersion: "5.3.21",
		SrcRelease: "24.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD and LGPLv2 and Sleepycat"}},
	{Name: "libffi", Version: "3.0.13", Release: "18.amzn2.0.2", Arch: "x86_64", SrcName: "libffi", SrcVersion: "3.0.13",
		SrcRelease: "18.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT and Public Domain"}},
	{Name: "libgcc", Version: "7.3.1", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "gcc", SrcVersion: "7.3.1",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"}},
	{Name: "libgcrypt", Version: "1.5.3", Release: "14.amzn2.0.2", Arch: "x86_64", SrcName: "libgcrypt", SrcVersion: "1.5.3",
		SrcRelease: "14.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "libgpg-error", Version: "1.12", Release: "3.amzn2.0.3", Arch: "x86_64", SrcName: "libgpg-error", SrcVersion: "1.12",
		SrcRelease: "3.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "libidn2", Version: "2.0.4", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "libidn2", SrcVersion: "2.0.4",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"(GPLv2+ or LGPLv3+) and GPLv3+"}},
	{Name: "libmetalink", Version: "0.1.2", Release: "7.amzn2.0.2", Arch: "x86_64", SrcName: "libmetalink", SrcVersion: "0.1.2",
		SrcRelease: "7.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "libmount", Version: "2.30.2", Release: "2.amzn2.0.4", Arch: "x86_64", SrcName: "util-linux", SrcVersion: "2.30.2",
		SrcRelease: "2.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "libnghttp2", Version: "1.31.1", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "nghttp2", SrcVersion: "1.31.1",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "libselinux", Version: "2.5", Release: "12.amzn2.0.2", Arch: "x86_64", SrcName: "libselinux", SrcVersion: "2.5",
		SrcRelease: "12.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"Public Domain"}},
	{Name: "libsepol", Version: "2.5", Release: "8.1.amzn2.0.2", Arch: "x86_64", SrcName: "libsepol", SrcVersion: "2.5",
		SrcRelease: "8.1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "libssh2", Version: "1.4.3", Release: "12.amzn2.2", Arch: "x86_64", SrcName: "libssh2", SrcVersion: "1.4.3",
		SrcRelease: "12.amzn2.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD"}},
	{Name: "libstdc++", Version: "7.3.1", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "gcc", SrcVersion: "7.3.1",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"}},
	{Name: "libtasn1", Version: "4.10", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "libtasn1", SrcVersion: "4.10",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+ and LGPLv2+"}},
	{Name: "libunistring", Version: "0.9.3", Release: "9.amzn2.0.2", Arch: "x86_64", SrcName: "libunistring", SrcVersion: "0.9.3",
		SrcRelease: "9.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv3+"}},
	{Name: "libuuid", Version: "2.30.2", Release: "2.amzn2.0.4", Arch: "x86_64", SrcName: "util-linux", SrcVersion: "2.30.2",
		SrcRelease: "2.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD"}},
	{Name: "libverto", Version: "0.2.5", Release: "4.amzn2.0.2", Arch: "x86_64", SrcName: "libverto", SrcVersion: "0.2.5",
		SrcRelease: "4.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "libxml2", Version: "2.9.1", Release: "6.amzn2.3.2", Arch: "x86_64", SrcName: "libxml2", SrcVersion: "2.9.1",
		SrcRelease: "6.amzn2.3.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "lua", Version: "5.1.4", Release: "15.amzn2.0.2", Arch: "x86_64", SrcName: "lua", SrcVersion: "5.1.4",
		SrcRelease: "15.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "ncurses", Version: "6.0", Release: "8.20170212.amzn2.1.2", Arch: "x86_64", SrcName: "ncurses", SrcVersion: "6.0",
		SrcRelease: "8.20170212.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "ncurses-base", Version: "6.0", Release: "8.20170212.amzn2.1.2", Arch: "noarch", SrcName: "ncurses", SrcVersion: "6.0",
		SrcRelease: "8.20170212.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "ncurses-libs", Version: "6.0", Release: "8.20170212.amzn2.1.2", Arch: "x86_64", SrcName: "ncurses", SrcVersion: "6.0",
		SrcRelease: "8.20170212.amzn2.1.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "nspr", Version: "4.19.0", Release: "1.amzn2", Arch: "x86_64", SrcName: "nspr", SrcVersion: "4.19.0",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}},
	{Name: "nss", Version: "3.36.0", Release: "7.amzn2", Arch: "x86_64", SrcName: "nss", SrcVersion: "3.36.0",
		SrcRelease: "7.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}},
	{Name: "nss-pem", Version: "1.0.3", Release: "5.amzn2", Arch: "x86_64", SrcName: "nss-pem", SrcVersion: "1.0.3",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MPLv1.1"}},
	{Name: "nss-softokn", Version: "3.36.0", Release: "5.amzn2", Arch: "x86_64", SrcName: "nss-softokn", SrcVersion: "3.36.0",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}},
	{Name: "nss-softokn-freebl", Version: "3.36.0", Release: "5.amzn2", Arch: "x86_64", SrcName: "nss-softokn", SrcVersion: "3.36.0",
		SrcRelease: "5.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}},
	{Name: "nss-sysinit", Version: "3.36.0", Release: "7.amzn2", Arch: "x86_64", SrcName: "nss", SrcVersion: "3.36.0",
		SrcRelease: "7.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}},
	{Name: "nss-tools", Version: "3.36.0", Release: "7.amzn2", Arch: "x86_64", SrcName: "nss", SrcVersion: "3.36.0",
		SrcRelease: "7.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}},
	{Name: "nss-util", Version: "3.36.0", Release: "1.amzn2", Arch: "x86_64", SrcName: "nss-util", SrcVersion: "3.36.0",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MPLv2.0"}},
	{Name: "openldap", Version: "2.4.44", Release: "15.amzn2", Arch: "x86_64", SrcName: "openldap", SrcVersion: "2.4.44",
		SrcRelease: "15.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"OpenLDAP"}},
	{Name: "openssl-libs", Version: "1.0.2k", Release: "16.amzn2.1.1", Arch: "x86_64", SrcName: "openssl", SrcVersion: "1.0.2k",
		SrcRelease: "16.amzn2.1.1", Epoch: 1, SrcEpoch: 1, Layer: types.Layer{}, Licenses: []string{"OpenSSL"}},
	{Name: "p11-kit", Version: "0.23.5", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "p11-kit", SrcVersion: "0.23.5",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD"}},
	{Name: "p11-kit-trust", Version: "0.23.5", Release: "3.amzn2.0.2", Arch: "x86_64", SrcName: "p11-kit", SrcVersion: "0.23.5",
		SrcRelease: "3.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD"}},
	{Name: "pcre", Version: "8.32", Release: "17.amzn2.0.2", Arch: "x86_64", SrcName: "pcre", SrcVersion: "8.32",
		SrcRelease: "17.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"BSD"}},
	{Name: "pinentry", Version: "0.8.1", Release: "17.amzn2.0.2", Arch: "x86_64", SrcName: "pinentry", SrcVersion: "0.8.1",
		SrcRelease: "17.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+"}},
	{Name: "popt", Version: "1.13", Release: "16.amzn2.0.2", Arch: "x86_64", SrcName: "popt", SrcVersion: "1.13",
		SrcRelease: "16.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "pth", Version: "2.0.7", Release: "23.amzn2.0.2", Arch: "x86_64", SrcName: "pth", SrcVersion: "2.0.7",
		SrcRelease: "23.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "pygpgme", Version: "0.3", Release: "9.amzn2.0.2", Arch: "x86_64", SrcName: "pygpgme", SrcVersion: "0.3",
		SrcRelease: "9.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "pyliblzma", Version: "0.5.3", Release: "11.amzn2.0.2", Arch: "x86_64", SrcName: "pyliblzma", SrcVersion: "0.5.3",
		SrcRelease: "11.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv3+"}},
	{Name: "python", Version: "2.7.14", Release: "58.amzn2.0.4", Arch: "x86_64", SrcName: "python", SrcVersion: "2.7.14",
		SrcRelease: "58.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"Python"}},
	{Name: "python-iniparse", Version: "0.4", Release: "9.amzn2", Arch: "noarch", SrcName: "python-iniparse", SrcVersion: "0.4",
		SrcRelease: "9.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"MIT"}},
	{Name: "python-libs", Version: "2.7.14", Release: "58.amzn2.0.4", Arch: "x86_64", SrcName: "python", SrcVersion: "2.7.14",
		SrcRelease: "58.amzn2.0.4", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"Python"}},
	{Name: "python-pycurl", Version: "7.19.0", Release: "19.amzn2.0.2", Arch: "x86_64", SrcName: "python-pycurl", SrcVersion: "7.19.0",
		SrcRelease: "19.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+ or MIT"}},
	{Name: "python-urlgrabber", Version: "3.10", Release: "8.amzn2", Arch: "noarch", SrcName: "python-urlgrabber", SrcVersion: "3.10",
		SrcRelease: "8.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "pyxattr", Version: "0.5.1", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "pyxattr", SrcVersion: "0.5.1",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "readline", Version: "6.2", Release: "10.amzn2.0.2", Arch: "x86_64", SrcName: "readline", SrcVersion: "6.2",
		SrcRelease: "10.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "rpm", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+"}},
	{Name: "rpm-build-libs", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+ and LGPLv2+ with exceptions"}},
	{Name: "rpm-libs", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+ and LGPLv2+ with exceptions"}},
	{Name: "rpm-python", Version: "4.11.3", Release: "25.amzn2.0.3", Arch: "x86_64", SrcName: "rpm", SrcVersion: "4.11.3",
		SrcRelease: "25.amzn2.0.3", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+"}},
	{Name: "sed", Version: "4.2.2", Release: "5.amzn2.0.2", Arch: "x86_64", SrcName: "sed", SrcVersion: "4.2.2",
		SrcRelease: "5.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv3+"}},
	{Name: "setup", Version: "2.8.71", Release: "10.amzn2", Arch: "noarch", SrcName: "setup", SrcVersion: "2.8.71",
		SrcRelease: "10.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"Public Domain"}},
	{Name: "shared-mime-info", Version: "1.8", Release: "4.amzn2", Arch: "x86_64", SrcName: "shared-mime-info", SrcVersion: "1.8",
		SrcRelease: "4.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+"}},
	{Name: "sqlite", Version: "3.7.17", Release: "8.amzn2.0.2", Arch: "x86_64", SrcName: "sqlite", SrcVersion: "3.7.17",
		SrcRelease: "8.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"Public Domain"}},
	{Name: "system-release", Version: "2", Release: "10.amzn2", Arch: "x86_64", SrcName: "system-release", SrcVersion: "2",
		SrcRelease: "10.amzn2", Epoch: 1, SrcEpoch: 1, Layer: types.Layer{}, Licenses: []string{"GPLv2"}},
	{Name: "tzdata", Version: "2018i", Release: "1.amzn2", Arch: "noarch", SrcName: "tzdata", SrcVersion: "2018i",
		SrcRelease: "1.amzn2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"Public Domain"}},
	{Name: "vim-minimal", Version: "7.4.160", Release: "4.amzn2.0.16", Arch: "x86_64", SrcName: "vim", SrcVersion: "7.4.160",
		SrcRelease: "4.amzn2.0.16", Epoch: 2, SrcEpoch: 2, Layer: types.Layer{}, Licenses: []string{"Vim"}},
	{Name: "xz-libs", Version: "5.2.2", Release: "1.amzn2.0.2", Arch: "x86_64", SrcName: "xz", SrcVersion: "5.2.2",
		SrcRelease: "1.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"LGPLv2+"}},
	{Name: "yum", Version: "3.4.3", Release: "158.amzn2.0.2", Arch: "noarch", SrcName: "yum", SrcVersion: "3.4.3",
		SrcRelease: "158.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+"}},
	{Name: "yum-metadata-parser", Version: "1.1.4", Release: "10.amzn2.0.2", Arch: "x86_64", SrcName: "yum-metadata-parser", SrcVersion: "1.1.4",
		SrcRelease: "10.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2"}},
	{Name: "yum-plugin-ovl", Version: "1.1.31", Release: "46.amzn2.0.1", Arch: "noarch", SrcName: "yum-utils", SrcVersion: "1.1.31",
		SrcRelease: "46.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+"}},
	{Name: "yum-plugin-priorities", Version: "1.1.31", Release: "46.amzn2.0.1", Arch: "noarch", SrcName: "yum-utils", SrcVersion: "1.1.31",
		SrcRelease: "46.amzn2.0.1", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"GPLv2+"}},
	{Name: "zlib", Version: "1.2.7", Release: "17.amzn2.0.2", Arch: "x86_64", SrcName: "zlib", SrcVersion: "1.2.7",
		SrcRelease: "17.amzn2.0.2", Epoch: 0, SrcEpoch: 0, Layer: types.Layer{}, Licenses: []string{"zlib and Boost"}},
}
