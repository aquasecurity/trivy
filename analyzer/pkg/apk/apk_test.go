package apk

import (
	"bufio"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/fanal/types"
)

func TestParseApkInfo(t *testing.T) {
	var tests = map[string]struct {
		path string
		pkgs []types.Package
	}{
		"Valid": {
			path: "./testdata/apk",
			pkgs: []types.Package{
				{Name: "musl", Version: "1.1.14-r10", SrcName: "musl", SrcVersion: "1.1.14-r10", License: "MIT"},
				{Name: "busybox", Version: "1.24.2-r9", SrcName: "busybox", SrcVersion: "1.24.2-r9", License: "GPL2"},
				{Name: "alpine-baselayout", Version: "3.0.3-r0", SrcName: "alpine-baselayout", SrcVersion: "3.0.3-r0", License: "GPL2"},
				{Name: "alpine-keys", Version: "1.1-r0", SrcName: "alpine-keys", SrcVersion: "1.1-r0", License: "GPL"},
				{Name: "zlib", Version: "1.2.8-r2", SrcName: "zlib", SrcVersion: "1.2.8-r2", License: "zlib"},
				{Name: "libcrypto1.0", Version: "1.0.2h-r1", SrcName: "openssl", SrcVersion: "1.0.2h-r1", License: "openssl"},
				{Name: "libssl1.0", Version: "1.0.2h-r1", SrcName: "openssl", SrcVersion: "1.0.2h-r1", License: "openssl"},
				{Name: "apk-tools", Version: "2.6.7-r0", SrcName: "apk-tools", SrcVersion: "2.6.7-r0", License: "GPL2"},
				{Name: "scanelf", Version: "1.1.6-r0", SrcName: "pax-utils", SrcVersion: "1.1.6-r0", License: "GPL2"},
				{Name: "musl-utils", Version: "1.1.14-r10", SrcName: "musl", SrcVersion: "1.1.14-r10", License: "MIT BSD GPL2+"},
				{Name: "libc-utils", Version: "0.7-r0", SrcName: "libc-dev", SrcVersion: "0.7-r0", License: "GPL"},
				{Name: "pkgconf", Version: "1.6.0-r0", SrcName: "pkgconf", SrcVersion: "1.6.0-r0", License: "ISC"},
				{Name: "sqlite-libs", Version: "3.26.0-r3", SrcName: "sqlite", SrcVersion: "3.26.0-r3", License: "Public-Domain"},
				{Name: "test", Version: "2.9.11_pre20061021-r2", SrcName: "test-parent", SrcVersion: "2.9.11_pre20061021-r2", License: "Public-Domain"},
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
		pkgs := a.parseApkInfo(scanner)
		assert.Equal(t, v.pkgs, pkgs)
	}
}
