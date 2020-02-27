package photon

import (
	"reflect"
	"testing"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
)

func TestAnalyze(t *testing.T) {
	var tests = map[string]struct {
		path    string
		os      types.OS
		wantErr error
	}{
		"photon1.0": {
			path: "./testdata/photon_1",
			os:   types.OS{Family: os.Photon, Name: "1.0"},
		},
		"photon2.0": {
			path: "./testdata/photon_2",
			os:   types.OS{Family: os.Photon, Name: "2.0"},
		},
		"photon3.0": {
			path: "./testdata/photon_3",
			os:   types.OS{Family: os.Photon, Name: "3.0"},
		},
		"Invalid": {
			path:    "./testdata/not_photon",
			wantErr: os.AnalyzeOSError,
		},
	}
	a := photonOSAnalyzer{}
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
