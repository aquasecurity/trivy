package apk

import (
	"bufio"
	"os"
	"reflect"
	"testing"

	"github.com/aquasecurity/fanal/types"
	"github.com/kylelemons/godebug/pretty"
)

func TestParseApkInfo(t *testing.T) {
	var tests = map[string]struct {
		path string
		pkgs []types.Package
	}{
		"Valid": {
			path: "./testdata/apk",
			pkgs: []types.Package{
				{Name: "musl", Version: "1.1.14-r10"},
				{Name: "busybox", Version: "1.24.2-r9"},
				{Name: "alpine-baselayout", Version: "3.0.3-r0"},
				{Name: "alpine-keys", Version: "1.1-r0"},
				{Name: "zlib", Version: "1.2.8-r2"},
				{Name: "openssl", Version: "1.0.2h-r1"},
				{Name: "libcrypto1.0", Version: "1.0.2h-r1"},
				{Name: "libssl1.0", Version: "1.0.2h-r1"},
				{Name: "apk-tools", Version: "2.6.7-r0"},
				{Name: "pax-utils", Version: "1.1.6-r0"},
				{Name: "scanelf", Version: "1.1.6-r0"},
				{Name: "musl-utils", Version: "1.1.14-r10"},
				{Name: "libc-dev", Version: "0.7-r0"},
				{Name: "libc-utils", Version: "0.7-r0"},
				{Name: "pkgconf", Version: "1.6.0-r0"},
				{Name: "sqlite", Version: "3.26.0-r3"},
				{Name: "sqlite-libs", Version: "3.26.0-r3"},
				{Name: "test", Version: "2.9.11_pre20061021-r2"},
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
		if !reflect.DeepEqual(v.pkgs, pkgs) {
			t.Errorf("[%s]\n%s", testname, pretty.Compare(v.pkgs, pkgs))
		}
	}
}
