package rpm

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParseRpmInfo(t *testing.T) {
	var tests = map[string]struct {
		path string
		pkgs types.Packages
	}{
		"Valid": {
			path: "./testdata/valid",
			// cp ./testdata/valid /path/to/testdir/Packages
			// rpm -qa --dbpath /path/to/testdir --queryformat "\{Name: \"%{NAME}\", Epoch: %{RPMTAG_EPOCHNUM}, Version: \"%{VERSION}\", Release: \"%{RELEASE}\", Arch: \"%{ARCH}\", Modularitylabel: \"%{RPMTAG_MODULARITYLABEL}\", Licenses: \[\]string\{\"%{LICENSE}\"\}, Maintainer: \"%{RPMTAG_VENDOR}\", Digest: \"md5:%{SIGMD5}\",\n" | sed "s/(none)//g" > 1.txt
			// rpm -qa --dbpath /path/to/testdir --queryformat "%{SOURCERPM}-%{RPMTAG_EPOCHNUM}\n" | awk -F"-" '{printf("SrcName: \""$0"\", SrcEpoch: "$NF", SrcVersion: \""$(NF-2)"\", SrcRelease: \""$(NF-1)"\"},\n")}' | sed -E 's/-[0-9.]+-.+.src.rpm-[0-9]//' | sed 's/.src.rpm//g' > 2.txt
			// paste -d " " 1.txt 2.txt
			pkgs: requiredValidPackages,
		},
		"ValidBig": {
			path: "./testdata/valid_big",
			// cp ./testdata/valid_big /path/to/testdir/Packages
			// rpm -qa --dbpath /path/to/testdir --queryformat "\{Name: \"%{NAME}\", Epoch: %{RPMTAG_EPOCHNUM}, Version: \"%{VERSION}\", Release: \"%{RELEASE}\", Arch: \"%{ARCH}\", Modularitylabel: \"%{RPMTAG_MODULARITYLABEL}\", Licenses: \[\]string\{\"%{LICENSE}\"\}, Maintainer: \"%{RPMTAG_VENDOR}\", Digest: \"md5:%{SIGMD5}\",\n" | sed "s/(none)//g" > 1.txt
			// rpm -qa --dbpath /path/to/testdir --queryformat "%{SOURCERPM}-%{RPMTAG_EPOCHNUM}\n" | awk -F"-" '{printf("SrcName: \""$0"\", SrcEpoch: "$NF", SrcVersion: \""$(NF-2)"\", SrcRelease: \""$(NF-1)"\"},\n")}' | sed -E 's/-[0-9.]+-.+.src.rpm-[0-9]//' | sed 's/.src.rpm//g' > 2.txt
			// paste -d " " 1.txt 2.txt
			pkgs: requiredValidBigPackages,
		},
		"ValidWithModularitylabel": {
			path: "./testdata/valid_with_modularitylabel",
			// cp ./testdata/valid_with_modularitylabel /path/to/testdir/Packages
			// rpm -qa --dbpath /path/to/testdir --queryformat "\{Name: \"%{NAME}\", Epoch: %{RPMTAG_EPOCHNUM}, Version: \"%{VERSION}\", Release: \"%{RELEASE}\", Arch: \"%{ARCH}\", Modularitylabel: \"%{RPMTAG_MODULARITYLABEL}\", Licenses: \[\]string\{\"%{LICENSE}\"\}, Maintainer: \"%{RPMTAG_VENDOR}\", Digest: \"md5:%{SIGMD5}\",\n" | sed "s/(none)//g" > 1.txt
			// rpm -qa --dbpath /path/to/testdir --queryformat "%{SOURCERPM}-%{RPMTAG_EPOCHNUM}\n" | awk -F"-" '{printf("SrcName: \""$0"\", SrcEpoch: "$NF", SrcVersion: \""$(NF-2)"\", SrcRelease: \""$(NF-1)"\"},\n")}' | sed -E 's/-[0-9.]+-.+.src.rpm-[0-9]//' | sed 's/.src.rpm//g' > 2.txt
			// paste -d " " 1.txt 2.txt
			pkgs: requiredValidWithModularitylabelPackages,
		},
	}
	a := rpmPkgAnalyzer{}
	for testname, tc := range tests {
		t.Run(testname, func(t *testing.T) {
			f, err := os.Open(tc.path)
			require.NoError(t, err)
			defer f.Close()

			got, _, err := a.parsePkgInfo(f)
			require.NoError(t, err)

			sort.Sort(tc.pkgs)
			sort.Sort(got)

			for i := range got {
				got[i].ID = ""
				got[i].DependsOn = nil // TODO: add tests
			}

			assert.Equal(t, tc.pkgs, got)
		})
	}
}

func Test_splitFileName(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantName string
		wantVer  string
		wantRel  string
		wantErr  bool
	}{
		{
			name:     "valid name",
			filename: "glibc-2.17-307.el7.1.src.rpm",
			wantName: "glibc",
			wantVer:  "2.17",
			wantRel:  "307.el7.1",
			wantErr:  false,
		},
		{
			name:     "invalid name",
			filename: "elasticsearch-5.6.16-1-src.rpm",
			wantName: "",
			wantVer:  "",
			wantRel:  "",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVer, gotRel, err := splitFileName(tt.filename)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantVer, gotVer)
			assert.Equal(t, tt.wantRel, gotRel)
		})
	}
}
