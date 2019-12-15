package suse

import (
	"reflect"
	"testing"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/os"
)

func TestAnalyze(t *testing.T) {
	var tests = map[string]struct {
		path    string
		os      analyzer.OS
		wantErr error
	}{
		"OpenSUSELeap15.0": {
			path: "./testdata/opensuse_leap_150",
			os:   analyzer.OS{Family: os.OpenSUSELeap, Name: "15.0"},
		},
		"OpenSUSELeap15.1": {
			path: "./testdata/opensuse_leap_151",
			os:   analyzer.OS{Family: os.OpenSUSELeap, Name: "15.1"},
		},
		"OpenSUSELeap42.3": {
			path: "./testdata/opensuse_leap_423",
			os:   analyzer.OS{Family: os.OpenSUSELeap, Name: "42.3"},
		},
		"SLES12": {
			path: "./testdata/sles_12",
			os:   analyzer.OS{Family: os.SLES, Name: "12"},
		},
		"SLES15": {
			path: "./testdata/sles_15",
			os:   analyzer.OS{Family: os.SLES, Name: "15"},
		},
		"SLES15.1": {
			path: "./testdata/sles_151",
			os:   analyzer.OS{Family: os.SLES, Name: "15.1"},
		},
		"openSUSE Tumbleweed": {
			path: "./testdata/opensuse_leap_tumbleweed",
			os:   analyzer.OS{Family: os.OpenSUSETumbleweed, Name: "20191204"},
		},
		"Invalid": {
			path:    "./testdata/not_suse",
			wantErr: os.AnalyzeOSError,
		},
	}
	a := suseOSAnalyzer{}
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
