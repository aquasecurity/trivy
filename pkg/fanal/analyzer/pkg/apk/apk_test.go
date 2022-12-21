package apk

import (
	"bufio"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParseApkInfo(t *testing.T) {
	var tests = map[string]struct {
		path      string
		wantPkgs  []types.Package
		wantFiles []string
	}{
		"Valid": {
			path: "./testdata/apk",
			wantPkgs: []types.Package{
				{
					ID:         "musl@1.1.14-r10",
					Name:       "musl",
					Version:    "1.1.14-r10",
					SrcName:    "musl",
					SrcVersion: "1.1.14-r10",
					Licenses:   []string{"MIT"},
				},
				{
					ID:         "busybox@1.24.2-r9",
					Name:       "busybox",
					Version:    "1.24.2-r9",
					SrcName:    "busybox",
					SrcVersion: "1.24.2-r9",
					Licenses:   []string{"GPL-2.0"},
					DependsOn:  []string{"musl@1.1.14-r10"},
				},
				{
					ID:         "alpine-baselayout@3.0.3-r0",
					Name:       "alpine-baselayout",
					Version:    "3.0.3-r0",
					SrcName:    "alpine-baselayout",
					SrcVersion: "3.0.3-r0",
					Licenses:   []string{"GPL-2.0"},
					DependsOn:  []string{"busybox@1.24.2-r9", "musl@1.1.14-r10"},
				},
				{
					ID:         "alpine-keys@1.1-r0",
					Name:       "alpine-keys",
					Version:    "1.1-r0",
					SrcName:    "alpine-keys",
					SrcVersion: "1.1-r0",
					Licenses:   []string{"GPL-3.0"},
				},
				{
					ID:         "zlib@1.2.8-r2",
					Name:       "zlib",
					Version:    "1.2.8-r2",
					SrcName:    "zlib",
					SrcVersion: "1.2.8-r2",
					Licenses:   []string{"Zlib"},
					DependsOn:  []string{"musl@1.1.14-r10"},
				},
				{
					ID:         "libcrypto1.0@1.0.2h-r1",
					Name:       "libcrypto1.0",
					Version:    "1.0.2h-r1",
					SrcName:    "openssl",
					SrcVersion: "1.0.2h-r1",
					Licenses:   []string{"openssl"},
					DependsOn:  []string{"musl@1.1.14-r10", "zlib@1.2.8-r2"},
				},
				{
					ID:         "libssl1.0@1.0.2h-r1",
					Name:       "libssl1.0",
					Version:    "1.0.2h-r1",
					SrcName:    "openssl",
					SrcVersion: "1.0.2h-r1",
					Licenses:   []string{"openssl"},
					DependsOn: []string{
						"libcrypto1.0@1.0.2h-r1",
						"musl@1.1.14-r10",
					},
				},
				{
					ID:         "apk-tools@2.6.7-r0",
					Name:       "apk-tools",
					Version:    "2.6.7-r0",
					SrcName:    "apk-tools",
					SrcVersion: "2.6.7-r0",
					Licenses:   []string{"GPL-2.0"},
					DependsOn: []string{
						"libcrypto1.0@1.0.2h-r1",
						"libssl1.0@1.0.2h-r1",
						"musl@1.1.14-r10",
						"zlib@1.2.8-r2",
					},
				},
				{
					ID:         "scanelf@1.1.6-r0",
					Name:       "scanelf",
					Version:    "1.1.6-r0",
					SrcName:    "pax-utils",
					SrcVersion: "1.1.6-r0",
					Licenses:   []string{"GPL-2.0"},
					DependsOn:  []string{"musl@1.1.14-r10"},
				},
				{
					ID:         "musl-utils@1.1.14-r10",
					Name:       "musl-utils",
					Version:    "1.1.14-r10",
					SrcName:    "musl",
					SrcVersion: "1.1.14-r10",
					Licenses:   []string{"MIT", "BSD-3-Clause", "GPL-2.0"},
					DependsOn: []string{
						"musl@1.1.14-r10",
						"scanelf@1.1.6-r0",
					},
				},
				{
					ID:         "libc-utils@0.7-r0",
					Name:       "libc-utils",
					Version:    "0.7-r0",
					SrcName:    "libc-dev",
					SrcVersion: "0.7-r0",
					Licenses:   []string{"GPL-3.0"},
					DependsOn:  []string{"musl-utils@1.1.14-r10"},
				},
				{
					ID:         "pkgconf@1.6.0-r0",
					Name:       "pkgconf",
					Version:    "1.6.0-r0",
					SrcName:    "pkgconf",
					SrcVersion: "1.6.0-r0",
					Licenses:   []string{"ISC"},
					DependsOn:  []string{"musl@1.1.14-r10"},
				},

				{
					ID:         "sqlite-libs@3.26.0-r3",
					Name:       "sqlite-libs",
					Version:    "3.26.0-r3",
					SrcName:    "sqlite",
					SrcVersion: "3.26.0-r3",
					Licenses:   []string{"Public-Domain"},
					DependsOn:  []string{"musl@1.1.14-r10"},
				},

				{
					ID:         "test@2.9.11_pre20061021-r2",
					Name:       "test",
					Version:    "2.9.11_pre20061021-r2",
					SrcName:    "test-parent",
					SrcVersion: "2.9.11_pre20061021-r2",
					Licenses:   []string{"Public-Domain"},
					DependsOn: []string{
						"pkgconf@1.6.0-r0",
						"sqlite-libs@3.26.0-r3",
					},
				},
			},
			wantFiles: []string{
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
			},
		},
	}
	a := alpinePkgAnalyzer{}
	for testname, v := range tests {
		read, err := os.Open(v.path)
		if err != nil {
			t.Errorf("%s : can't open file %s", testname, v.path)
		}
		scanner := bufio.NewScanner(read)
		gotPkgs, gotFiles := a.parseApkInfo(scanner)
		assert.Equal(t, v.wantPkgs, gotPkgs)
		assert.Equal(t, v.wantFiles, gotFiles)
	}
}
