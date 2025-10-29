package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

type accessTokenResponse struct {
	Token string `json:"token"`
}

const (
	accessTokenPath = "/api-keys/access-tokens"
)

func GetAccessToken(ctx context.Context, opts flag.Options) (string, error) {
	if opts.CloudOptions.CloudToken == "" {
		return "", xerrors.New("no cloud token provided for getting access token from Trivy Cloud")
	}

	if opts.CloudOptions.ApiURL == "" {
		return "", xerrors.New("no API URL provided for getting access token from Trivy Cloud")
	}

	logger := log.WithPrefix(log.PrefixCloud)

	client := xhttp.Client()
	u, err := url.JoinPath(opts.CloudOptions.ApiURL, accessTokenPath)
	if err != nil {
		return "", xerrors.Errorf("failed to join server URL and token path: %w", err)
	}
	logger.Debug("Requesting access token from Trivy Cloud", log.String("url", u))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, http.NoBody)
	if err != nil {
		return "", xerrors.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", opts.CloudOptions.CloudToken))
	resp, err := client.Do(req)
	if err != nil {
		return "", xerrors.Errorf("failed to get access token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", xerrors.Errorf("failed to get access token: received status code %d", resp.StatusCode)
	}

	var tokenResponse accessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", xerrors.Errorf("failed to decode access token response: %w", err)
	}

	logger.Debug("Created a new access token")
	return tokenResponse.Token, nil
}
