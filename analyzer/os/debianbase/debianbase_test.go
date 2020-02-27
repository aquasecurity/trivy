package debianbase

import (
	"reflect"
	"testing"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/os"
)

func TestAnalyze(t *testing.T) {
	var tests = map[string]struct {
		path    string
		os      types.OS
		wantErr error
	}{
		"Debian9": {
			path: "./testdata/debian_9",
			os:   types.OS{Family: os.Debian, Name: "9.8"},
		},
		"DebianSid": {
			path: "./testdata/debian_sid",
			os:   types.OS{Family: os.Debian, Name: "buster/sid"},
		},
		"Ubuntu18": {
			path: "./testdata/ubuntu_18",
			os:   types.OS{Family: os.Ubuntu, Name: "18.04"},
		},
		"Invalid": {
			path:    "./testdata/not_debianbase",
			wantErr: os.AnalyzeOSError,
		},
	}
	a := debianbaseOSAnalyzer{}
	for testname, v := range tests {
		fileMap, err := os.GetFileMap(v.path)
		if err != nil {
			t.Errorf("%s : catch the error : %v", testname, err)
		}
		osInfo, err := a.Analyze(fileMap)
		if v.wantErr != nil {
			if err == nil {
				t.Errorf("%s : expected error but no error", testname)
			}
			if !xerrors.Is(err, v.wantErr) {
				t.Errorf("[%s]\nexpected : %v\nactual : %v", testname, v.wantErr, err)
			}
		}
		if !reflect.DeepEqual(v.os, osInfo) {
			t.Errorf("[%s]\nexpected : %v\nactual : %v", testname, v.os, osInfo)
		}
	}
}
