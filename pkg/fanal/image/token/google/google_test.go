package google

import (
	"reflect"
	"testing"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestCheckOptions(t *testing.T) {
	var tests = map[string]struct {
		domain  string
		opt     types.DockerOption
		gcr     *Registry
		wantErr error
	}{
		"InvalidURL": {
			domain:  "alpine:3.9",
			opt:     types.DockerOption{},
			wantErr: types.InvalidURLPattern,
		},
		"NoOption": {
			domain: "gcr.io",
			opt:    types.DockerOption{},
			gcr:    &Registry{domain: "gcr.io"},
		},
		"CredOption": {
			domain: "gcr.io",
			opt:    types.DockerOption{GcpCredPath: "/path/to/file.json"},
			gcr:    &Registry{domain: "gcr.io", Store: store.NewGCRCredStore("/path/to/file.json")},
		},
	}

	for testname, v := range tests {
		g := &Registry{}
		err := g.CheckOptions(v.domain, v.opt)
		if v.wantErr != nil {
			if err == nil {
				t.Errorf("%s : expected error but no error", testname)
				continue
			}
			if !xerrors.Is(err, v.wantErr) {
				t.Errorf("[%s]\nexpected error based on %v\nactual : %v", testname, v.wantErr, err)
			}
			continue
		}
		if !reflect.DeepEqual(v.gcr, g) {
			t.Errorf("[%s]\nexpected : %v\nactual : %v", testname, v.gcr, g)
		}
	}
}
