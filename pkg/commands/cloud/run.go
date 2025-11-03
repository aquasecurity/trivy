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
	"github.com/aquasecurity/trivy/pkg/types"
)

// UpdateOptsForProIntegration checks if the Trivy Pro integration is enabled and configures the options accordingly
// if there are variables that are already set that would cause a conflict, we return an error.
// if the token is not provided, we don't need to check the integration and can return early.
func UpdateOptsForProIntegration(ctx context.Context, opts *flag.Options) error {
	if opts.ProOptions.ProToken == "" {
		return nil
	}

	logger := log.WithPrefix(log.PrefixCloud)
	accessToken, err := cloud.GetAccessToken(ctx, *opts)
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
		if err := cloud.GetConfigs(ctx, opts, accessToken); err != nil {
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
