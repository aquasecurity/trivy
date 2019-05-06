package redhatbase

import (
	"reflect"
	"testing"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/analyzer/os"
)

func TestAnalyze(t *testing.T) {
	var tests = map[string]struct {
		path    string
		os      analyzer.OS
		wantErr error
	}{
		"CentOS": {
			path: "./testdata/centos",
			os:   analyzer.OS{Family: os.CentOS, Name: "7.6.1810"},
		},
		"Fedora29": {
			path: "./testdata/fedora_29",
			os:   analyzer.OS{Family: os.Fedora, Name: "29"},
		},
		"Fedora31": {
			path: "./testdata/fedora_31",
			os:   analyzer.OS{Family: os.Fedora, Name: "31"},
		},
		"Oracle7": {
			path: "./testdata/oracle_7",
			os:   analyzer.OS{Family: os.Oracle, Name: "7.6"},
		},
		"Redhat6": {
			path: "./testdata/redhat_6",
			os:   analyzer.OS{Family: os.RedHat, Name: "6.2"},
		},
		"Invalid": {
			path:    "./testdata/not_redhatbase",
			wantErr: os.AnalyzeOSError,
		},
	}
	a := redhatOSAnalyzer{}
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
