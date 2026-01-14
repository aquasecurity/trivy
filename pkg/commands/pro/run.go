package pro

import (
	"context"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/extension"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/pro"
	"github.com/aquasecurity/trivy/pkg/pro/hooks"
	"github.com/aquasecurity/trivy/pkg/types"
)

func Login(ctx context.Context, opts flag.Options) error {
	logger := log.WithPrefix(log.PrefixPro)
	var token string
	var err error

	if opts.ProOptions.AppURL == "" {
		return xerrors.New("no app URL provided for logging in to Trivy Pro")
	}

	if opts.ProOptions.ProToken != "" {
		logger.Debug("Using existing token from flags")
		token = opts.ProOptions.ProToken
	} else {
		logger.Debug("Logging in to Trivy Pro")
		token, err = pro.Login(ctx, opts)
		if err != nil {
			return xerrors.Errorf("failed to login: %w", err)
		}
	}
	return pro.SaveToken(ctx, opts, token)
}

func Logout() error {
	logger := log.WithPrefix(log.PrefixPro)
	logger.Debug("Logging out of Trivy Pro")
	if err := pro.DeleteTokenFromKeyring(); err != nil {
		return xerrors.Errorf("failed to logout: %w", err)
	}
	logger.Info("Logged out of Trivy Pro")
	return nil
}

// Status checks if the user is logged in to Trivy Pro by checking the token in the keyring and the validating against the API.
// If the user is not logged in, it returns nil.
// If the user is logged in, it returns an error if the access token is invalid.
func Status(ctx context.Context, opts flag.Options) error {
	logger := log.WithPrefix(log.PrefixPro)
	logger.Debug("Checking status of Trivy Pro")
	token, err := pro.GetTokenFromKeyring()
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			logger.Info("No token found in keyring, not logged in to Trivy Pro")
			return nil
		}
		return xerrors.Errorf("failed to get token from keyring: %w", err)
	}

	logger.Debug("Found token in keyring, checking access token")
	opts.ProOptions.ProToken = token
	_, err = pro.GetAccessToken(ctx, opts)
	if err != nil {
		logger.Info("Invalid credentials found for Trivy Pro, please login again", log.Err(err))
		return nil
	}

	logger.Info("Valid credentials found for Trivy Pro")
	return nil
}

// UpdateOptsForProIntegration checks if the Trivy Pro integration is enabled and configures the options accordingly
// if there are variables that are already set that would cause a conflict, we return an error.
// if the token is not provided, we don't need to check the integration and can return early.
func UpdateOptsForProIntegration(ctx context.Context, opts *flag.Options) error {
	logger := log.WithPrefix(log.PrefixPro)
	if opts.ProOptions.ProToken == "" {
		// check the keyring for a token
		token, err := pro.GetTokenFromKeyring()
		if err != nil {
			logger.Warn("An error occurred while checking for a token from the keyring", log.Err(err))
		}
		if token == "" {
			logger.Debug("No token found in keyring, continuing with scan")
			return nil
		}
		opts.ProOptions.ProToken = token
	}

	accessToken, err := pro.GetAccessToken(ctx, *opts)
	if err != nil {
		return xerrors.Errorf("failed to get access token for Trivy Pro: %w", err)
	}

	if opts.ProOptions.UseServerSideScanning {
		// ensure that the server address hasn't been already set, this would be an unacceptable config conflict.
		if opts.ServerAddr != "" && opts.ServerAddr != opts.ProOptions.TrivyServerURL {
			return xerrors.Errorf("server-side scanning is enabled, but server address is already set to %s", opts.ServerAddr)
		}

		logger.Debug("Using server-side scanning for Trivy Pro, updating opts")
		opts.ServerAddr = opts.ProOptions.TrivyServerURL
		opts.CustomHeaders.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	}

	if opts.ProOptions.SecretConfig && opts.Scanners.Enabled(types.SecretScanner) {
		if err := pro.GetConfigs(ctx, opts, accessToken); err != nil {
			return xerrors.Errorf("failed to download configs: %w", err)
		}
	}

	// if uploading results we need to register a report hook with the required details
	if opts.ProOptions.UploadResults {
		reportHook := hooks.NewReportHook(opts.ProOptions.ApiURL, accessToken)
		extension.RegisterHook(reportHook)
	}

	return nil
}
