package apk

import (
	"bufio"
	"os"
	"path/filepath"
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
				filepath.Join("lib", "libc.musl-x86_64.so.1"),
				filepath.Join("lib", "ld-musl-x86_64.so.1"),

				// busybox-1.24.2-r9
				filepath.Join("bin", "busybox"),
				filepath.Join("bin", "sh"),
				filepath.Join("etc", "securetty"),
				filepath.Join("etc", "udhcpd.conf"),
				filepath.Join("etc", "logrotate.d", "acpid"),

				// alpine-baselayout-3.0.3-r0
				filepath.Join("etc", "hosts"),
				filepath.Join("etc", "sysctl.conf"),
				filepath.Join("etc", "group"),
				filepath.Join("etc", "protocols"),
				filepath.Join("etc", "fstab"),
				filepath.Join("etc", "mtab"),
				filepath.Join("etc", "profile"),
				filepath.Join("etc", "TZ"),
				filepath.Join("etc", "shells"),
				filepath.Join("etc", "motd"),
				filepath.Join("etc", "inittab"),
				filepath.Join("etc", "hostname"),
				filepath.Join("etc", "modules"),
				filepath.Join("etc", "services"),
				filepath.Join("etc", "shadow"),
				filepath.Join("etc", "passwd"),
				filepath.Join("etc", "profile.d", "color_prompt"),
				filepath.Join("etc", "sysctl.d", "00-alpine.conf"),
				filepath.Join("etc", "modprobe.d", "i386.conf"),
				filepath.Join("etc", "modprobe.d", "blacklist.conf"),
				filepath.Join("etc", "modprobe.d", "aliases.conf"),
				filepath.Join("etc", "modprobe.d", "kms.conf"),
				filepath.Join("etc", "crontabs", "root"),
				filepath.Join("sbin", "mkmntdirs"),
				filepath.Join("var", "spool", "cron", "crontabs"),

				// alpine-keys-1.1-r0
				filepath.Join("etc", "apk", "keys", "alpine-devel@lists.alpinelinux.org-4d07755e.rsa.pub"),
				filepath.Join("etc", "apk", "keys", "alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub"),
				filepath.Join("etc", "apk", "keys", "alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub"),
				filepath.Join("etc", "apk", "keys", "alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub"),
				filepath.Join("etc", "apk", "keys", "alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub"),

				// zlib-1.2.8-r2
				filepath.Join("lib", "libz.so.1.2.8"),
				filepath.Join("lib", "libz.so.1"),

				// libcrypto1.0-1.0.2h-r1
				filepath.Join("lib", "libcrypto.so.1.0.0"),
				filepath.Join("usr", "bin", "c_rehash"),
				filepath.Join("usr", "lib", "libcrypto.so.1.0.0"),
				filepath.Join("usr", "lib", "engines", "libubsec.so"),
				filepath.Join("usr", "lib", "engines", "libatalla.so"),
				filepath.Join("usr", "lib", "engines", "libcapi.so"),
				filepath.Join("usr", "lib", "engines", "libgost.so"),
				filepath.Join("usr", "lib", "engines", "libcswift.so"),
				filepath.Join("usr", "lib", "engines", "libchil.so"),
				filepath.Join("usr", "lib", "engines", "libgmp.so"),
				filepath.Join("usr", "lib", "engines", "libnuron.so"),
				filepath.Join("usr", "lib", "engines", "lib4758cca.so"),
				filepath.Join("usr", "lib", "engines", "libsureware.so"),
				filepath.Join("usr", "lib", "engines", "libpadlock.so"),
				filepath.Join("usr", "lib", "engines", "libaep.so"),

				// libssl1.0-1.0.2h-r1
				filepath.Join("lib/libssl.so.1.0.0"),
				filepath.Join("usr/lib/libssl.so.1.0.0"),

				// apk-tools-2.6.7-r0
				filepath.Join("sbin/apk"),

				// scanelf-1.1.6-r0
				filepath.Join("usr/bin/scanelf"),

				// musl-utils-1.1.14-r10
				filepath.Join("sbin/ldconfig"),
				filepath.Join("usr/bin/iconv"),
				filepath.Join("usr/bin/ldd"),
				filepath.Join("usr/bin/getconf"),
				filepath.Join("usr/bin/getent"),

				// libc-utils-0.7-r0

				// pkgconf-1.6.0-r0
				filepath.Join("usr/bin/pkgconf"),
				filepath.Join("usr/bin/pkg-config"),
				filepath.Join("usr/lib/libpkgconf.so.3.0.0"),
				filepath.Join("usr/lib/libpkgconf.so.3"),
				filepath.Join("usr/share/aclocal/pkg.m4"),

				// sqlite-libs-3.26.0-r3
				filepath.Join("usr/lib/libsqlite3.so.0"),
				filepath.Join("usr/lib/libsqlite3.so.0.8.6"),

				// test-2.9.11_pre20061021-r2
				filepath.Join("usr/lib/libsqlite3.so"),
				filepath.Join("usr/lib/pkgconfig/sqlite3.pc"),
				filepath.Join("usr/include/sqlite3ext.h"),
				filepath.Join("usr/include/sqlite3.h"),
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
