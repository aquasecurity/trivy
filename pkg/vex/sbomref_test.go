package vex_test

import (
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const (
	vexExternalRef = "/openvex"
	vexUnknown     = "/unknown"
)

func setUpServer(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == vexExternalRef {
			f, err := os.Open("testdata/" + vexExternalRef + ".json")
			require.NoError(t, err)
			defer f.Close()

			_, err = io.Copy(w, f)
			require.NoError(t, err)
		} else if r.URL.Path == vexUnknown {
			f, err := os.Open("testdata/" + vexUnknown + ".json")
			require.NoError(t, err)
			defer f.Close()

			_, err = io.Copy(w, f)
			require.NoError(t, err)
		}

		http.NotFound(w, r)
		return
	}))
	return s
}

func setupTestReport(s *httptest.Server, path string) *types.Report {
	r := types.Report{
		ArtifactType: artifact.TypeCycloneDX,
		BOM:          &core.BOM{},
	}
	r.BOM.AddExternalReferences([]core.ExternalReference{{
		URL:  s.URL + path,
		Type: core.ExternalReferenceVex,
	}})

	return &r
}

func TestRetrieveExternalVEXDocuments(t *testing.T) {
	s := setUpServer(t)
	t.Cleanup(s.Close)

	t.Run("external vex retrieval", func(t *testing.T) {
		set, err := vex.NewSBOMReferenceSet(setupTestReport(s, vexExternalRef))
		require.NoError(t, err)
		require.Equal(t, 1, len(set.Vexes))
	})

	t.Run("incompatible external vex", func(t *testing.T) {
		set, err := vex.NewSBOMReferenceSet(setupTestReport(s, vexUnknown))
		require.NoError(t, err)
		require.Equal(t, 0, len(set.Vexes))
	})
}
