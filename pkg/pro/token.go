package pro

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/zalando/go-keyring"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

type accessTokenResponse struct {
	Token string `json:"token"`
}

type keyringPayload struct {
	Token  string `json:"token"`
	AppURL string `json:"app_url"`
	ApiURL string `json:"api_url"`
}

const (
	accessTokenPath = "/api-keys/access-tokens"
	KeyringService  = "trivy-pro"
	KeyringAccount  = "trivy-pro"
)

func GetAccessToken(ctx context.Context, opts flag.Options) (string, error) {
	if opts.ProOptions.ProToken == "" {
		return "", xerrors.New("no pro token provided for getting access token from Trivy Pro")
	}

	if opts.ProOptions.ApiURL == "" {
		return "", xerrors.New("no API URL provided for getting access token from Trivy Pro")
	}

	logger := log.WithPrefix(log.PrefixPro)

	client := xhttp.Client()
	u, err := url.JoinPath(opts.ProOptions.ApiURL, accessTokenPath)
	if err != nil {
		return "", xerrors.Errorf("failed to join server URL and token path: %w", err)
	}
	logger.Debug("Requesting access token from Trivy Pro", log.String("url", u))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, http.NoBody)
	if err != nil {
		return "", xerrors.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", opts.ProOptions.ProToken))
	resp, err := client.Do(req)
	if err != nil {
		return "", xerrors.Errorf("failed to get access token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", xerrors.Errorf("failed to get access token from Trivy Pro: received status code %d", resp.StatusCode)
	}

	var tokenResponse accessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", xerrors.Errorf("failed to decode access token response: %w", err)
	}

	logger.Debug("Created a new access token")
	return tokenResponse.Token, nil
}

// SaveToken saves the token to the keyring
// The token is saved in the keyring with the following format:
//
//	{
//		"token": "token",
//		"app_url": "app_url",
//		"api_url": "api_url"
//	}
//
// This is all the information that is required to verify the token etc
func SaveToken(_ context.Context, opts flag.Options, token string) error {
	logger := log.WithPrefix(log.PrefixPro)
	if token == "" {
		return xerrors.New("no token provided to save")
	}

	logger.Debug("Saving token to keyring", log.String("app_url", opts.ProOptions.AppURL), log.String("api_url", opts.ProOptions.ApiURL))
	payload := keyringPayload{
		Token:  token,
		AppURL: opts.ProOptions.AppURL,
		ApiURL: opts.ProOptions.ApiURL,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return xerrors.Errorf("failed to marshal keyring payload: %w", err)
	}

	err = keyring.Set(KeyringService, KeyringAccount, string(payloadBytes))
	if err != nil {
		return xerrors.Errorf("failed to save token to keyring: %w", err)
	}

	logger.Info("Token securely saved to keyring")
	return nil
}

func GetTokenFromKeyring() (string, error) {
	tokenBody, err := keyring.Get(KeyringService, KeyringAccount)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", xerrors.Errorf("failed to get token from keyring: %w", err)
		}
		return "", err
	}

	var tokenPayload keyringPayload
	if err := json.Unmarshal([]byte(tokenBody), &tokenPayload); err != nil {
		return "", xerrors.Errorf("failed to unmarshal token from keyring: %w", err)
	}
	return tokenPayload.Token, nil
}

func DeleteTokenFromKeyring() error {
	logger := log.WithPrefix(log.PrefixPro)
	logger.Debug("Deleting token from keyring")
	err := keyring.Delete(KeyringService, KeyringAccount)
	if err != nil && err != keyring.ErrNotFound {
		return xerrors.Errorf("failed to delete token from keyring: %w", err)
	}
	logger.Info("Token deleted from keyring")
	return nil
}
