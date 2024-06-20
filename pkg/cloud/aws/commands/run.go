package commands

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-aws/pkg/errs"
	awsScanner "github.com/aquasecurity/trivy-aws/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/cloud"
	"github.com/aquasecurity/trivy/pkg/cloud/aws/config"
	"github.com/aquasecurity/trivy/pkg/cloud/aws/scanner"
	"github.com/aquasecurity/trivy/pkg/cloud/report"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/doc"
)

var allSupportedServicesFunc = awsScanner.AllSupportedServices

func getAccountIDAndRegion(ctx context.Context, region, endpoint string) (string, string, error) {
	log.DebugContext(ctx, "Looking for AWS credentials provider...")

	cfg, err := config.LoadDefaultAWSConfig(ctx, region, endpoint)
	if err != nil {
		return "", "", err
	}

	svc := sts.NewFromConfig(cfg)

	log.DebugContext(ctx, "Looking up AWS caller identity...")
	result, err := svc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", xerrors.Errorf("failed to discover AWS caller identity: %w", err)
	}
	if result.Account == nil {
		return "", "", xerrors.Errorf("missing account id for aws account")
	}
	log.DebugContext(ctx, "Verified AWS credentials for account!", log.String("account", *result.Account))
	return *result.Account, cfg.Region, nil
}

func validateServicesInput(services, skipServices []string) error {
	for _, s := range services {
		for _, ss := range skipServices {
			if s == ss {
				return xerrors.Errorf("service: %s specified to both skip and include", s)
			}
		}
	}
	return nil
}

func processOptions(ctx context.Context, opt *flag.Options) error {
	if err := validateServicesInput(opt.Services, opt.SkipServices); err != nil {
		return err
	}

	// support comma separated services too
	var splitServices []string
	for _, service := range opt.Services {
		splitServices = append(splitServices, strings.Split(service, ",")...)
	}
	opt.Services = splitServices

	var splitSkipServices []string
	for _, skipService := range opt.SkipServices {
		splitSkipServices = append(splitSkipServices, strings.Split(skipService, ",")...)
	}
	opt.SkipServices = splitSkipServices

	if len(opt.Services) != 1 && opt.ARN != "" {
		return xerrors.Errorf("you must specify the single --service which the --arn relates to")
	}

	if opt.Account == "" || opt.Region == "" {
		var err error
		opt.Account, opt.Region, err = getAccountIDAndRegion(ctx, opt.Region, opt.Endpoint)
		if err != nil {
			return err
		}
	}

	err := filterServices(ctx, opt)
	if err != nil {
		return err
	}

	log.DebugContext(ctx, "Scanning services", log.Any("services", opt.Services))
	return nil
}

func filterServices(ctx context.Context, opt *flag.Options) error {
	switch {
	case len(opt.Services) == 0 && len(opt.SkipServices) == 0:
		log.DebugContext(ctx, "No service(s) specified, scanning all services...")
		opt.Services = allSupportedServicesFunc()
	case len(opt.SkipServices) > 0:
		log.DebugContext(ctx, "Excluding services", log.Any("services", opt.SkipServices))
		for _, s := range allSupportedServicesFunc() {
			if slices.Contains(opt.SkipServices, s) {
				continue
			}
			if !slices.Contains(opt.Services, s) {
				opt.Services = append(opt.Services, s)
			}
		}
	case len(opt.Services) > 0:
		log.DebugContext(ctx, "Specific services were requested...",
			log.String("services", strings.Join(opt.Services, ", ")))
		for _, service := range opt.Services {
			var found bool
			supported := allSupportedServicesFunc()
			for _, allowed := range supported {
				if allowed == service {
					found = true
					break
				}
			}
			if !found {
				return xerrors.Errorf("service '%s' is not currently supported - supported services are: %s", service, strings.Join(supported, ", "))
			}
		}
	}
	return nil
}

func Run(ctx context.Context, opt flag.Options) error {
	ctx, cancel := context.WithTimeout(ctx, opt.GlobalOptions.Timeout)
	defer cancel()

	ctx = log.WithContextPrefix(ctx, "aws")

	var err error
	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			// e.g. https://aquasecurity.github.io/trivy/latest/docs/configuration/
			log.WarnContext(ctx, fmt.Sprintf("Provide a higher timeout value, see %s", doc.URL("/docs/configuration/", "")))
		}
	}()

	if err := processOptions(ctx, &opt); err != nil {
		return err
	}

	results, cached, err := scanner.NewScanner().Scan(ctx, opt)
	if err != nil {
		var aerr errs.AdapterError
		if errors.As(err, &aerr) {
			for _, e := range aerr.Errors() {
				log.WarnContext(ctx, "Adapter error", log.Err(e))
			}
		} else {
			return xerrors.Errorf("aws scan error: %w", err)
		}
	}

	log.DebugContext(ctx, "Writing report to output...")

	sort.Slice(results, func(i, j int) bool {
		return results[i].Rule().AVDID < results[j].Rule().AVDID
	})

	res := results.GetFailed()
	if opt.MisconfOptions.IncludeNonFailures {
		res = results
	}

	r := report.New(cloud.ProviderAWS, opt.Account, opt.Region, res, opt.Services)
	if err := report.Write(ctx, r, opt, cached); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	return operation.Exit(opt, r.Failed(), types.Metadata{})
}
