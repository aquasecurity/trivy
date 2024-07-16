package apk

import (
	"bufio"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var pkgs = []types.Package{
	{
		ID:         "musl@1.1.14-r10",
		Name:       "musl",
		Version:    "1.1.14-r10",
		SrcName:    "musl",
		SrcVersion: "1.1.14-r10",
		Licenses:   []string{"MIT"},
		Arch:       "x86_64",
		Digest:     "sha1:d68b402f35f57750f49156b0cb4e886a2ad35d2d",
		InstalledFiles: []string{
			"lib/libc.musl-x86_64.so.1",
			"lib/ld-musl-x86_64.so.1",
		},
	},
	{
		ID:         "busybox@1.24.2-r9",
		Name:       "busybox",
		Version:    "1.24.2-r9",
		SrcName:    "busybox",
		SrcVersion: "1.24.2-r9",
		Licenses:   []string{"GPL-2.0-only"},
		DependsOn:  []string{"musl@1.1.14-r10"},
		Arch:       "x86_64",
		Digest:     "sha1:ca124719267cd0bedc2f4cb850a286ac13f0ad44",
		InstalledFiles: []string{
			"bin/busybox",
			"bin/sh",
			"etc/securetty",
			"etc/udhcpd.conf",
			"etc/logrotate.d/acpid",
		},
	},
	{
		ID:         "alpine-baselayout@3.0.3-r0",
		Name:       "alpine-baselayout",
		Version:    "3.0.3-r0",
		SrcName:    "alpine-baselayout",
		SrcVersion: "3.0.3-r0",
		Licenses:   []string{"GPL-2.0-only"},
		DependsOn: []string{
			"busybox@1.24.2-r9",
			"musl@1.1.14-r10",
		},
		Arch:   "x86_64",
		Digest: "sha1:a214896150411d72dd1fafdb32d1c6c4855cccfa",
		InstalledFiles: []string{
			"etc/hosts",
			"etc/sysctl.conf",
			"etc/group",
			"etc/protocols",
			"etc/fstab",
			"etc/mtab",
			"etc/profile",
			"etc/TZ",
			"etc/shells",
			"etc/motd",
			"etc/inittab",
			"etc/hostname",
			"etc/modules",
			"etc/services",
			"etc/shadow",
			"etc/passwd",
			"etc/profile.d/color_prompt",
			"etc/sysctl.d/00-alpine.conf",
			"etc/modprobe.d/i386.conf",
			"etc/modprobe.d/blacklist.conf",
			"etc/modprobe.d/aliases.conf",
			"etc/modprobe.d/kms.conf",
			"etc/crontabs/root",
			"sbin/mkmntdirs",
			"var/spool/cron/crontabs",
		},
	},
	{
		ID:         "alpine-keys@1.1-r0",
		Name:       "alpine-keys",
		Version:    "1.1-r0",
		SrcName:    "alpine-keys",
		SrcVersion: "1.1-r0",
		Licenses:   []string{"GPL-2.0-or-later"},
		Arch:       "x86_64",
		Digest:     "sha1:4def7ffaee6aeba700c1d62570326f75cbb8fa25",
		InstalledFiles: []string{
			"etc/apk/keys/alpine-devel@lists.alpinelinux.org-4d07755e.rsa.pub",
			"etc/apk/keys/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub",
			"etc/apk/keys/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
			"etc/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
			"etc/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
		},
	},
	{
		ID:         "zlib@1.2.8-r2",
		Name:       "zlib",
		Version:    "1.2.8-r2",
		SrcName:    "zlib",
		SrcVersion: "1.2.8-r2",
		Licenses:   []string{"Zlib"},
		DependsOn:  []string{"musl@1.1.14-r10"},
		Arch:       "x86_64",
		Digest:     "sha1:efd04d34d40aa8eb331480127364c27a8ba760ef",
		InstalledFiles: []string{
			"lib/libz.so.1.2.8",
			"lib/libz.so.1",
		},
	},
	{
		ID:         "libcrypto1.0@1.0.2h-r1",
		Name:       "libcrypto1.0",
		Version:    "1.0.2h-r1",
		SrcName:    "openssl",
		SrcVersion: "1.0.2h-r1",
		Licenses:   []string{"OpenSSL"},
		DependsOn: []string{
			"musl@1.1.14-r10",
			"zlib@1.2.8-r2",
		},
		Arch:   "x86_64",
		Digest: "sha1:65c860ff8f103b664f40ba849a3f5a51c69c8beb",
		InstalledFiles: []string{
			"lib/libcrypto.so.1.0.0",
			"usr/bin/c_rehash",
			"usr/lib/libcrypto.so.1.0.0",
			"usr/lib/engines/libubsec.so",
			"usr/lib/engines/libatalla.so",
			"usr/lib/engines/libcapi.so",
			"usr/lib/engines/libgost.so",
			"usr/lib/engines/libcswift.so",
			"usr/lib/engines/libchil.so",
			"usr/lib/engines/libgmp.so",
			"usr/lib/engines/libnuron.so",
			"usr/lib/engines/lib4758cca.so",
			"usr/lib/engines/libsureware.so",
			"usr/lib/engines/libpadlock.so",
			"usr/lib/engines/libaep.so",
		},
	},
	{
		ID:         "libssl1.0@1.0.2h-r1",
		Name:       "libssl1.0",
		Version:    "1.0.2h-r1",
		SrcName:    "openssl",
		SrcVersion: "1.0.2h-r1",
		Licenses:   []string{"OpenSSL"},
		Digest:     "sha1:7120f337e93b2b4c44e0f5f31a15b60dc678ca14",
		DependsOn: []string{
			"libcrypto1.0@1.0.2h-r1",
			"musl@1.1.14-r10",
		},
		Arch: "x86_64",
		InstalledFiles: []string{
			"lib/libssl.so.1.0.0",
			"usr/lib/libssl.so.1.0.0",
		},
	},
	{
		ID:         "apk-tools@2.6.7-r0",
		Name:       "apk-tools",
		Version:    "2.6.7-r0",
		SrcName:    "apk-tools",
		SrcVersion: "2.6.7-r0",
		Licenses:   []string{"GPL-2.0-only"},
		Digest:     "sha1:0990c0acd62b4175818c3a4cc60ed11f14e23bd8",
		DependsOn: []string{
			"libcrypto1.0@1.0.2h-r1",
			"libssl1.0@1.0.2h-r1",
			"musl@1.1.14-r10",
			"zlib@1.2.8-r2",
		},
		Arch: "x86_64",
		InstalledFiles: []string{
			"sbin/apk",
		},
	},
	{
		ID:         "scanelf@1.1.6-r0",
		Name:       "scanelf",
		Version:    "1.1.6-r0",
		SrcName:    "pax-utils",
		SrcVersion: "1.1.6-r0",
		Licenses:   []string{"GPL-2.0-only"},
		Digest:     "sha1:f9bab817c5ad93e92a6218bc0f7596b657c02d90",
		DependsOn:  []string{"musl@1.1.14-r10"},
		Arch:       "x86_64",
		InstalledFiles: []string{
			"usr/bin/scanelf",
		},
	},
	{
		ID:         "musl-utils@1.1.14-r10",
		Name:       "musl-utils",
		Version:    "1.1.14-r10",
		SrcName:    "musl",
		SrcVersion: "1.1.14-r10",
		Licenses: []string{
			"MIT",
			"BSD-3-Clause",
			"GPL-2.0-or-later",
		},
		Digest: "sha1:608aa1dd39eff7bc6615d3e5e33383750f8f5ecc",
		DependsOn: []string{
			"musl@1.1.14-r10",
			"scanelf@1.1.6-r0",
		},
		Arch: "x86_64",
		InstalledFiles: []string{
			"sbin/ldconfig",
			"usr/bin/iconv",
			"usr/bin/ldd",
			"usr/bin/getconf",
			"usr/bin/getent",
		},
	},
	{
		ID:         "libc-utils@0.7-r0",
		Name:       "libc-utils",
		Version:    "0.7-r0",
		SrcName:    "libc-dev",
		SrcVersion: "0.7-r0",
		Licenses:   []string{"GPL-2.0-or-later"},
		Digest:     "sha1:9055bc7afd76cf2672198042f72fc4a5ed4fa961",
		DependsOn:  []string{"musl-utils@1.1.14-r10"},
		Arch:       "x86_64",
		//InstalledFiles: []string{},
	},
	{
		ID:         "pkgconf@1.6.0-r0",
		Name:       "pkgconf",
		Version:    "1.6.0-r0",
		SrcName:    "pkgconf",
		SrcVersion: "1.6.0-r0",
		Licenses:   []string{"ISC"},
		Digest:     "sha1:e6242ac29589c8a84a4b179b491ea7c29fce66a9",
		DependsOn:  []string{"musl@1.1.14-r10"},
		Arch:       "x86_64",
		InstalledFiles: []string{
			"usr/bin/pkgconf",
			"usr/bin/pkg-config",
			"usr/lib/libpkgconf.so.3.0.0",
			"usr/lib/libpkgconf.so.3",
			"usr/share/aclocal/pkg.m4",
		},
	},
	{
		ID:         "sqlite-libs@3.26.0-r3",
		Name:       "sqlite-libs",
		Version:    "3.26.0-r3",
		SrcName:    "sqlite",
		SrcVersion: "3.26.0-r3",
		Licenses:   []string{"Public-Domain"},
		Digest:     "sha1:1464946c3a5f0dd5a67ca1af930fc17af7a74474",
		DependsOn:  []string{"musl@1.1.14-r10"},
		Arch:       "x86_64",
		InstalledFiles: []string{
			"usr/lib/libsqlite3.so.0",
			"usr/lib/libsqlite3.so.0.8.6",
		},
	},
	{
		ID:         "test@2.9.11_pre20061021-r2",
		Name:       "test",
		Version:    "2.9.11_pre20061021-r2",
		SrcName:    "test-parent",
		SrcVersion: "2.9.11_pre20061021-r2",
		Licenses:   []string{"Public-Domain"},
		Digest:     "sha1:f0bf315ec54828188910e4a665c00bc48bdbdd7d",
		DependsOn: []string{
			"pkgconf@1.6.0-r0",
			"sqlite-libs@3.26.0-r3",
		},
		Arch: "x86_64",
		InstalledFiles: []string{
			"usr/lib/libsqlite3.so",
			"usr/lib/pkgconfig/sqlite3.pc",
			"usr/include/sqlite3ext.h",
			"usr/include/sqlite3.h",
		},
	},
	{
		ID:         "ada-libs@2.7.4-r0",
		Name:       "ada-libs",
		Version:    "2.7.4-r0",
		SrcName:    "ada",
		SrcVersion: "2.7.4-r0",
		Licenses: []string{
			"Apache-2.0",
			"MIT",
			"MPL-2.0",
		},
		Digest: "sha1:593154f80c440685448e0f52479725d7bc9b678d",
		DependsOn: []string{
			"musl@1.1.14-r10",
		},
		Arch: "x86_64",
		InstalledFiles: []string{
			"usr/lib/libada.so.2",
			"usr/lib/libada.so.2.7.4",
		},
	},
}

var files = []string{
	// musl-1.1.14-r10
	"lib/libc.musl-x86_64.so.1",
	"lib/ld-musl-x86_64.so.1",

	// busybox-1.24.2-r9
	"bin/busybox",
	"bin/sh",
	"etc/securetty",
	"etc/udhcpd.conf",
	"etc/logrotate.d/acpid",

	// alpine-baselayout-3.0.3-r0
	"etc/hosts",
	"etc/sysctl.conf",
	"etc/group",
	"etc/protocols",
	"etc/fstab",
	"etc/mtab",
	"etc/profile",
	"etc/TZ",
	"etc/shells",
	"etc/motd",
	"etc/inittab",
	"etc/hostname",
	"etc/modules",
	"etc/services",
	"etc/shadow",
	"etc/passwd",
	"etc/profile.d/color_prompt",
	"etc/sysctl.d/00-alpine.conf",
	"etc/modprobe.d/i386.conf",
	"etc/modprobe.d/blacklist.conf",
	"etc/modprobe.d/aliases.conf",
	"etc/modprobe.d/kms.conf",
	"etc/crontabs/root",
	"sbin/mkmntdirs",
	"var/spool/cron/crontabs",

	// alpine-keys-1.1-r0
	"etc/apk/keys/alpine-devel@lists.alpinelinux.org-4d07755e.rsa.pub",
	"etc/apk/keys/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub",
	"etc/apk/keys/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
	"etc/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
	"etc/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",

	// zlib-1.2.8-r2
	"lib/libz.so.1.2.8",
	"lib/libz.so.1",

	// libcrypto1.0-1.0.2h-r1
	"lib/libcrypto.so.1.0.0",
	"usr/bin/c_rehash",
	"usr/lib/libcrypto.so.1.0.0",
	"usr/lib/engines/libubsec.so",
	"usr/lib/engines/libatalla.so",
	"usr/lib/engines/libcapi.so",
	"usr/lib/engines/libgost.so",
	"usr/lib/engines/libcswift.so",
	"usr/lib/engines/libchil.so",
	"usr/lib/engines/libgmp.so",
	"usr/lib/engines/libnuron.so",
	"usr/lib/engines/lib4758cca.so",
	"usr/lib/engines/libsureware.so",
	"usr/lib/engines/libpadlock.so",
	"usr/lib/engines/libaep.so",

	// libssl1.0-1.0.2h-r1
	"lib/libssl.so.1.0.0",
	"usr/lib/libssl.so.1.0.0",

	// apk-tools-2.6.7-r0
	"sbin/apk",

	// scanelf-1.1.6-r0
	"usr/bin/scanelf",

	// musl-utils-1.1.14-r10
	"sbin/ldconfig",
	"usr/bin/iconv",
	"usr/bin/ldd",
	"usr/bin/getconf",
	"usr/bin/getent",

	// libc-utils-0.7-r0

	// pkgconf-1.6.0-r0
	"usr/bin/pkgconf",
	"usr/bin/pkg-config",
	"usr/lib/libpkgconf.so.3.0.0",
	"usr/lib/libpkgconf.so.3",
	"usr/share/aclocal/pkg.m4",

	// sqlite-libs-3.26.0-r3
	"usr/lib/libsqlite3.so.0",
	"usr/lib/libsqlite3.so.0.8.6",

	// test-2.9.11_pre20061021-r2
	"usr/lib/libsqlite3.so",
	"usr/lib/pkgconfig/sqlite3.pc",
	"usr/include/sqlite3ext.h",
	"usr/include/sqlite3.h",

	// ada-libs@2.5.1-r0
	"usr/lib/libada.so.2",
	"usr/lib/libada.so.2.7.4",
}

func TestParseApkInfo(t *testing.T) {
	var tests = []struct {
		name      string
		path      string
		wantPkgs  []types.Package
		wantFiles []string
	}{
		{
			name:      "happy path",
			path:      "./testdata/apk",
			wantPkgs:  pkgs,
			wantFiles: files,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := alpinePkgAnalyzer{}
			f, err := os.Open(tt.path)
			require.NoError(t, err)
			defer f.Close()
			scanner := bufio.NewScanner(f)
			gotPkgs, gotFiles := a.parseApkInfo(context.Background(), scanner)

			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantFiles, gotFiles)
		})
	}
}
