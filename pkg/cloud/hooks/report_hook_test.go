package hooks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

type mockReportServer struct {
	server              *httptest.Server
	uploadURLRequested  bool
	reportUploaded      bool
	uploadedReport      *types.Report
	returnUnauthorized  bool
	returnInvalidJSON   bool
	failUpload          bool
	presignedUploadPath string
}

func (m *mockReportServer) Start() {
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == presignedUploadUrl {
			m.handlePresignedURLRequest(w, r)
			return
		}

		if r.URL.Path == m.presignedUploadPath {
			m.handleReportUpload(w, r)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	m.presignedUploadPath = "/upload-report"
}

func (m *mockReportServer) handlePresignedURLRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Authorization") != "Bearer test-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if m.returnUnauthorized {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	m.uploadURLRequested = true

	if m.returnInvalidJSON {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid json`))
		return
	}

	uploadURL := m.server.URL + m.presignedUploadPath
	response := map[string]string{
		"uploadUrl": uploadURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (m *mockReportServer) handleReportUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if m.failUpload {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var report types.Report
	if err := json.Unmarshal(body, &report); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	m.reportUploaded = true
	m.uploadedReport = &report

	w.WriteHeader(http.StatusOK)
}

func (m *mockReportServer) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

func TestReportHook_Name(t *testing.T) {
	hook := NewReportHook("http://api.example.com", "test-token")
	assert.Equal(t, "Trivy Cloud Results Hook", hook.Name())
}

func TestReportHook_PreReport(t *testing.T) {
	hook := NewReportHook("http://api.example.com", "test-token")
	err := hook.PreReport(context.Background(), &types.Report{}, flag.Options{})
	assert.NoError(t, err)
}

func TestReportHook_PostReport(t *testing.T) {
	tests := []struct {
		name               string
		report             *types.Report
		returnUnauthorized bool
		returnInvalidJSON  bool
		failUpload         bool
		errorContains      string
	}{
		{
			name: "successful upload",
			report: &types.Report{
				ArtifactName: "test-artifact",
				ArtifactType: ftypes.TypeContainerImage,
				Results: types.Results{
					{
						Target: "test-target",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID: "CVE-2021-1234",
								PkgName:         "test-package",
								PkgID:           "test-package@1.0.0",
							},
						},
					},
				},
			},
		},
		{
			name: "empty report",
			report: &types.Report{
				ArtifactName: "empty-artifact",
				ArtifactType: ftypes.TypeContainerImage,
			},
		},
		{
			name: "invalid token 401 status code",
			report: &types.Report{
				ArtifactName: "test-artifact",
			},
			returnUnauthorized: true,
			errorContains:      "failed to get presigned upload URL",
		},
		{
			name: "unauthorized access",
			report: &types.Report{
				ArtifactName: "test-artifact",
			},
			returnUnauthorized: true,
			errorContains:      "failed to get presigned upload URL",
		},
		{
			name: "invalid json response",
			report: &types.Report{
				ArtifactName: "test-artifact",
			},
			returnInvalidJSON: true,
			errorContains:     "failed to decode upload URL response",
		},
		{
			name: "upload failure",
			report: &types.Report{
				ArtifactName: "test-artifact",
			},
			failUpload:    true,
			errorContains: "failed to upload results",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := &mockReportServer{
				returnUnauthorized: tt.returnUnauthorized,
				returnInvalidJSON:  tt.returnInvalidJSON,
				failUpload:         tt.failUpload,
			}
			mockServer.Start()
			defer mockServer.Close()

			hook := NewReportHook(mockServer.server.URL, "test-token")
			err := hook.PostReport(context.Background(), tt.report, flag.Options{})

			if tt.errorContains != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.errorContains)
				return
			}

			require.NoError(t, err)
			assert.True(t, mockServer.uploadURLRequested)
			assert.True(t, mockServer.reportUploaded)
			assert.Equal(t, tt.report.ArtifactName, mockServer.uploadedReport.ArtifactName)
		})
	}
}

func TestReportHook_uploadResults(t *testing.T) {
	tests := []struct {
		name          string
		jsonReport    []byte
		failUpload    bool
		errorContains string
	}{
		{
			name:       "successful upload",
			jsonReport: []byte(`{"artifactName": "test"}`),
		},
		{
			name:          "upload failure",
			jsonReport:    []byte(`{"artifactName": "test"}`),
			failUpload:    true,
			errorContains: "failed to upload results",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := &mockReportServer{
				failUpload: tt.failUpload,
			}
			mockServer.Start()
			defer mockServer.Close()

			hook := NewReportHook(mockServer.server.URL, "test-token")
			err := hook.uploadResults(context.Background(), tt.jsonReport)

			if tt.errorContains != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.errorContains)
				return
			}

			require.NoError(t, err)
			assert.True(t, mockServer.reportUploaded)
		})
	}
}

func TestReportHook_getPresignedUploadUrl(t *testing.T) {
	tests := []struct {
		name               string
		returnUnauthorized bool
		returnInvalidJSON  bool
		errorContains      string
		expectedURL        string
	}{
		{
			name: "successful request",
		},
		{
			name:               "unauthorized",
			returnUnauthorized: true,
			errorContains:      "failed to get upload URL",
		},
		{
			name:              "invalid json response",
			returnInvalidJSON: true,
			errorContains:     "failed to decode upload URL response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := &mockReportServer{
				returnUnauthorized: tt.returnUnauthorized,
				returnInvalidJSON:  tt.returnInvalidJSON,
			}
			mockServer.Start()
			defer mockServer.Close()

			hook := NewReportHook(mockServer.server.URL, "test-token")
			url, err := hook.getPresignedUploadUrl(context.Background())

			if tt.errorContains != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.errorContains)
				assert.Empty(t, url)
				return
			}

			require.NoError(t, err)
			assert.Contains(t, url, mockServer.server.URL)
			assert.Contains(t, url, "/upload-report")
		})
	}
}
