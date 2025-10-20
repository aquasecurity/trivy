package cloud

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cloud"
	"github.com/aquasecurity/trivy/pkg/cloud/hooks"
	"github.com/aquasecurity/trivy/pkg/extension"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

const GroupCloud = "cloud"

// Login performs a login to the Trivy Cloud Server service using the provided credentials.
func Login(ctx context.Context, opts flag.Options) error {
	creds := opts.CloudOptions.LoginCredentials
	if creds.Token == "" {
		return xerrors.New("token is required for Trivy Cloud login")
	}
	if opts.CloudOptions.TrivyServerUrl == "" {
		return xerrors.New("trivy server url is required for Trivy Cloud login")
	}
	if opts.CloudOptions.ApiUrl == "" {
		return xerrors.New("api url is required for Trivy Cloud login")
	}

	// load the existing config or get the default
	cloudConfig, err := cloud.Load()
	if err != nil {
		return xerrors.Errorf("failed to load Trivy Cloud config: %w", err)
	}
	cloudConfig.Token = creds.Token
	cloudConfig.Server.URL = opts.CloudOptions.TrivyServerUrl
	cloudConfig.Api.URL = opts.CloudOptions.ApiUrl

	if err := cloudConfig.Verify(ctx); err != nil {
		return xerrors.Errorf("failed to verify Trivy Cloud config: %w", err)
	}

	if err := cloudConfig.Save(); err != nil {
		return xerrors.Errorf("failed to save Trivy Cloud config: %w", err)
	}

	log.WithPrefix(log.PrefixCloud).Info("Trivy Cloud login successful")
	return nil
}

// Logout removes the Trivy cloud configuration from both keychain and config file.
func Logout() error {
	if err := cloud.Clear(); err != nil {
		return xerrors.Errorf("failed to clear Trivy Cloud configuration: %w", err)
	}

	log.WithPrefix(log.PrefixCloud).Info("Logged out of Trivy cloud and removed configuration")
	return nil
}

// CheckTrivyCloudStatus checks if the Trivy Cloud configuration file exists and verifies the token.
// If the token is valid, it sets the environment variables TRIVY_SERVER and TRIVY_TOKEN.
func CheckTrivyCloudStatus(cmd *cobra.Command) error {
	if cmd.GroupID == GroupCloud {
		return nil
	}

	logger := log.WithPrefix(log.PrefixCloud)
	cloudConfig, err := cloud.Load()
	if err != nil {
		logger.Error("Failed to load Trivy Cloud config file", log.Err(err))
		return nil
	}

	if cloudConfig != nil && cloudConfig.Verify(cmd.Context()) == nil {
		logger.Info("Trivy cloud is logged in")
		if cloudConfig.Server.Scanning.Enabled {
			logger.Info("Trivy Cloud server scanning is enabled")
			os.Setenv("TRIVY_SERVER", cloudConfig.Server.URL)
			os.Setenv("TRIVY_TOKEN_HEADER", "Authorization")
			os.Setenv("TRIVY_TOKEN", fmt.Sprintf("Bearer %s", cloudConfig.Token))
		}

		if cloudConfig.Server.Scanning.UploadResults {
			logger.Info("Trivy Cloud results upload is enabled")
			// add hook to upload the results to Trivy Cloud
			resultHook := hooks.NewResultsHook(cloudConfig)
			extension.RegisterHook(resultHook)
		}
	}

	return nil
}

func ListConfig() error {
	return cloud.ListConfig()
}

func EditConfig() error {
	return cloud.OpenConfigForEditing()
}

func SetConfig(attribute string, value any) error {
	return cloud.Set(attribute, value)
}

func UnsetConfig(attribute string) error {
	return cloud.Unset(attribute)
}
func GetConfig(attribute string) error {
	value, err := cloud.Get(attribute)
	if err != nil {
		return xerrors.Errorf("failed to get Trivy Cloud config: %w", err)
	}
	fmt.Println(value)
	return nil
}
