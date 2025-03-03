package vex_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

const (
	vexExternalRef = "/openvex"
	vexUnknown     = "/unknown"
	vexNotFound    = "/not-found"
)

func setUpServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case vexExternalRef:
			f, err := os.Open("testdata/" + vexExternalRef + ".json")
			if err != nil {
				t.Fatalf("failed to open testdata: %s", err)
			}
			defer f.Close()

			if _, err = io.Copy(w, f); err != nil {
				t.Fatalf("failed to copy testdata: %s", err)
			}
		case vexUnknown:
			f, err := os.Open("testdata/" + vexUnknown + ".json")
			if err != nil {
				t.Fatalf("failed to open testdata: %s", err)
			}
			defer f.Close()

			if _, err = io.Copy(w, f); err != nil {
				t.Fatalf("failed to copy testdata: %s", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

func setupTestReport(s *httptest.Server, path string) *types.Report {
	r := types.Report{
		ArtifactType: artifact.TypeCycloneDX,
		BOM:          &core.BOM{},
	}
	r.BOM.AddExternalReferences([]core.ExternalReference{{
		URL:  s.URL + path,
		Type: core.ExternalReferenceVEX,
	}})

	return &r
}

func setupEmptyTestReport() *types.Report {
	r := types.Report{
		ArtifactType: artifact.TypeCycloneDX,
		BOM:          &core.BOM{},
	}
	return &r
}

func TestRetrieveExternalVEXDocuments(t *testing.T) {
	s := setUpServer(t)
	t.Cleanup(s.Close)

	tests := []struct {
		name      string
		input     *types.Report
		wantVEXes int
		wantErr   bool
	}{
		{
			name:      "external vex retrieval",
			input:     setupTestReport(s, vexExternalRef),
			wantVEXes: 1,
			wantErr:   false,
		},
		{
			name:    "incompatible external vex",
			input:   setupTestReport(s, vexUnknown),
			wantErr: true,
		},
		{
			name:    "vex not found",
			input:   setupTestReport(s, vexNotFound),
			wantErr: true,
		},
		{
			name:      "no external reference",
			input:     setupEmptyTestReport(),
			wantVEXes: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vex.NewSBOMReferenceSet(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, lo.FromPtr(got).VEXes, tt.wantVEXes)
		})
	}
}
