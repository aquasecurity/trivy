package cloud

import (
	"context"
	"fmt"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cloud"
	"github.com/aquasecurity/trivy/pkg/cloud/hooks"
	"github.com/aquasecurity/trivy/pkg/extension"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

// UpdateOptsForCloudIntegration checks if the Trivy Cloud integration is enabled and configures the options accordingly
// if there are variables that are already set that would cause a conflict, we return an error.
// if the token is not provided, we don't need to check the integration and can return early.
func UpdateOptsForCloudIntegration(ctx context.Context, opts *flag.Options) error {
	if opts.CloudOptions.CloudToken == "" {
		return nil
	}

	logger := log.WithPrefix(log.PrefixCloud)
	accessToken, err := cloud.GetAccessToken(ctx, *opts)
	if err != nil {
		return xerrors.Errorf("failed to get access token for Trivy Cloud: %w", err)
	}

	if opts.CloudOptions.UseServerSideScanning {
		// ensure that the server address hasn't been already set, this would be an unacceptable config conflict.
		if opts.ServerAddr != "" && opts.ServerAddr != opts.CloudOptions.TrivyServerURL {
			return xerrors.Errorf("server-side scanning is enabled, but server address is already set to %s", opts.ServerAddr)
		}

		logger.Debug("Using server-side scanning for Trivy Cloud, updating opts")
		opts.ServerAddr = opts.CloudOptions.TrivyServerURL
		opts.CustomHeaders.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	}

	if opts.CloudOptions.SecretConfig || opts.CloudOptions.MisconfigConfig {
		if err := cloud.GetConfigs(ctx, opts, accessToken); err != nil {
			return xerrors.Errorf("failed to download configs: %w", err)
		}
	}

	// if uploading results we need to register a report hook with the required details
	if opts.CloudOptions.UploadResults {
		reportHook := hooks.NewReportHook(opts.CloudOptions.ApiURL, accessToken)
		extension.RegisterHook(reportHook)
	}

	return nil
}
