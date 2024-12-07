package vex_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		println(r.URL.Path)
		if r.URL.Path == vexExternalRef {
			f, err := os.Open("testdata/" + vexExternalRef + ".json")
			if err != nil {
				t.Error(err)
			}

			defer f.Close()

			_, err = io.Copy(w, f)
			if err != nil {
				t.Error(err)
			}
		} else if r.URL.Path == vexUnknown {
			f, err := os.Open("testdata/" + vexUnknown + ".json")
			if err != nil {
				t.Error(err)
			}
			defer f.Close()

			_, err = io.Copy(w, f)
			if err != nil {
				t.Error(err)
			}
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

	t.Run("external vex retrieval", func(t *testing.T) {
		set, err := vex.NewSBOMReferenceSet(setupTestReport(s, vexExternalRef))
		require.NoError(t, err)
		require.Len(t, set.VEXes, 1)
	})

	t.Run("incompatible external vex", func(t *testing.T) {
		_, err := vex.NewSBOMReferenceSet(setupTestReport(s, vexUnknown))
		require.Error(t, err)
	})

	t.Run("vex not found", func(t *testing.T) {
		_, err := vex.NewSBOMReferenceSet(setupTestReport(s, vexNotFound))
		require.Error(t, err)
	})

	t.Run("no external reference", func(t *testing.T) {
		set, err := vex.NewSBOMReferenceSet(setupEmptyTestReport())
		require.NoError(t, err)
		require.Nil(t, set)
	})
}
