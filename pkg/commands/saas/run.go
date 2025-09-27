package saas

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/saas"
)

const saasGroupID = "saas"

// Login performs a login to the Trivy Cloud Server service using the provided credentials.
func Login(ctx context.Context, opts flag.Options) error {
	logger := log.WithPrefix("trivy-cloud")
	creds := opts.SaasOptions.SaasCredentials
	if creds.Token == "" {
		return errors.New("token is required for SaaS login")
	}
	if opts.SaasOptions.SaasTrivyServerUrl == "" {
		return errors.New("trivy server url is required for SaaS login")
	}
	if opts.SaasOptions.SaasApiUrl == "" {
		return errors.New("api url is required for SaaS login")
	}

	cloudConfig := saas.CloudConfig{
		Token:     creds.Token,
		ServerUrl: opts.SaasOptions.SaasTrivyServerUrl,
		ApiUrl:    opts.SaasOptions.SaasApiUrl,
	}

	if err := cloudConfig.Verify(ctx); err != nil {
		return xerrors.Errorf("failed to verify SaaS config: %w", err)
	}

	if err := cloudConfig.Save(); err != nil {
		return xerrors.Errorf("failed to save SaaS config: %w", err)
	}

	logger.Info("Trivy Cloud login successful")
	return nil
}

// Logout removes the Trivy cloud configuration from both keychain and config file.
func Logout() error {
	logger := log.WithPrefix("trivy-cloud")

	if err := saas.Clear(); err != nil {
		return xerrors.Errorf("failed to clear SaaS configuration: %w", err)
	}

	logger.Info("Logged out of Trivy cloud and removed configuration")
	return nil
}

// CheckTrivyCloudStatus checks if the SaaS configuration file exists and verifies the token.
// If the token is valid, it sets the environment variables TRIVY_SERVER and TRIVY_TOKEN.
func CheckTrivyCloudStatus(cmd *cobra.Command) error {
	if cmd.GroupID == saasGroupID {
		return nil
	}

	logger := log.WithPrefix("trivy-cloud")
	cloudConfig, err := saas.Load()
	if err != nil {
		logger.Debug("Failed to load SaaS config file", log.Err(err))
	}

	if cloudConfig != nil && cloudConfig.Verify(cmd.Context()) == nil {
		logger.Info("Trivy cloud is logged in")
		os.Setenv("TRIVY_SERVER", cloudConfig.ServerUrl)
		os.Setenv("TRIVY_TOKEN_HEADER", "Authorization")
		os.Setenv("TRIVY_TOKEN", fmt.Sprintf("Bearer %s", cloudConfig.Token))
	}
	return nil
}
