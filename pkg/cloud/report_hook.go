package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

var (
	presignedUploadUrl = "/trivy-reports/upload-url"
)

type CloudPlatformResultsHook struct {
	name        string
	cloudConfig *CloudConfig
}

func NewResultsHook(cloudCfg *CloudConfig) *CloudPlatformResultsHook {
	return &CloudPlatformResultsHook{
		name:        "Trivy Cloud Results Hook",
		cloudConfig: cloudCfg,
	}
}

func (h *CloudPlatformResultsHook) Name() string {
	return h.name
}

// PreReport is not going go to be called so we return nil
func (h *CloudPlatformResultsHook) PreReport(_ context.Context, _ *types.Report, _ flag.Options) error {
	return nil
}

func (h *CloudPlatformResultsHook) PostReport(ctx context.Context, report *types.Report, _ flag.Options) error {
	logger := log.WithPrefix("trivy-cloud")
	logger.Debug("PostReport called with report")

	client := xhttp.ClientWithContext(ctx)
	jsonReport, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal report to JSON: %w", err)
	}

	return h.uploadResults(client, jsonReport)
}

func (h *CloudPlatformResultsHook) uploadResults(client *http.Client, jsonReport []byte) error {
	logger := log.WithPrefix("trivy-cloud")

	uploadUrl, err := h.getPresignedUploadUrl(client)
	if err != nil {
		return fmt.Errorf("failed to get presigned upload URL: %w", err)
	}

	// create a new request to upload the results
	req, err := http.NewRequest(http.MethodPut, uploadUrl, bytes.NewBuffer(jsonReport))
	if err != nil {
		return fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload results: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to upload results: received status code %d", resp.StatusCode)
	}

	logger.Info("Results uploaded successfully to Trivy Cloud")
	return nil
}

func (h *CloudPlatformResultsHook) getPresignedUploadUrl(client *http.Client) (string, error) {
	logger := log.WithPrefix("trivy-cloud")

	uploadUrl := h.cloudConfig.ApiUrl + presignedUploadUrl
	logger.Debug("Requesting result upload URL", log.String("uploadUrl", uploadUrl))

	req, err := http.NewRequest(http.MethodGet, uploadUrl, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+h.cloudConfig.Token)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get upload URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get upload URL: %w", err)
	}

	// read the upload URL from the response
	var uploadResponse struct {
		UploadURL string `json:"uploadUrl"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&uploadResponse); err != nil {
		return "", xerrors.Errorf("failed to decode upload URL response: %w", err)
	}

	return uploadResponse.UploadURL, nil
}
