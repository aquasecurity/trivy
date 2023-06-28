package commands

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/defsec/pkg/errs"
	awsScanner "github.com/aquasecurity/defsec/pkg/scanners/cloud/aws"
	"github.com/aquasecurity/trivy/pkg/cloud"
	"github.com/aquasecurity/trivy/pkg/cloud/aws/scanner"
	"github.com/aquasecurity/trivy/pkg/cloud/report"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	cr "github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

var allSupportedServicesFunc = awsScanner.AllSupportedServices

func getAccountIDAndRegion(ctx context.Context, region string) (string, string, error) {
	log.Logger.Debug("Looking for AWS credentials provider...")

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return "", "", err
	}
	if region != "" {
		cfg.Region = region
	}

	svc := sts.NewFromConfig(cfg)

	log.Logger.Debug("Looking up AWS caller identity...")
	result, err := svc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", xerrors.Errorf("failed to discover AWS caller identity: %w", err)
	}
	if result.Account == nil {
		return "", "", xerrors.Errorf("missing account id for aws account")
	}
	log.Logger.Debugf("Verified AWS credentials for account %s!", *result.Account)
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
		opt.Account, opt.Region, err = getAccountIDAndRegion(ctx, opt.Region)
		if err != nil {
			return err
		}
	}

	err := filterServices(opt)
	if err != nil {
		return err
	}

	log.Logger.Debug("scanning services: ", opt.Services)
	return nil
}

func filterServices(opt *flag.Options) error {
	if len(opt.Services) == 0 && len(opt.SkipServices) == 0 {
		log.Logger.Debug("No service(s) specified, scanning all services...")
		opt.Services = allSupportedServicesFunc()
	} else if len(opt.SkipServices) > 0 {
		log.Logger.Debug("excluding services: ", opt.SkipServices)
		for _, s := range allSupportedServicesFunc() {
			if slices.Contains(opt.SkipServices, s) {
				continue
			}
			if !slices.Contains(opt.Services, s) {
				opt.Services = append(opt.Services, s)
			}
		}
	} else if len(opt.Services) > 0 {
		log.Logger.Debugf("Specific services were requested: [%s]...", strings.Join(opt.Services, ", "))
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

	if err := log.InitLogger(opt.Debug, false); err != nil {
		return xerrors.Errorf("logger error: %w", err)
	}

	var err error
	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
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
				log.Logger.Warnf("Adapter error: %s", e)
			}
		} else {
			return xerrors.Errorf("aws scan error: %w", err)
		}
	}

	log.Logger.Debug("Writing report to output...")
	if opt.Compliance.Spec.ID != "" {
		convertedResults := report.ConvertResults(results, cloud.ProviderAWS, opt.Services)
		var crr []types.Results
		for _, r := range convertedResults {
			crr = append(crr, r.Results)
		}

		complianceReport, err := cr.BuildComplianceReport(crr, opt.Compliance)
		if err != nil {
			return xerrors.Errorf("compliance report build error: %w", err)
		}

		return cr.Write(complianceReport, cr.Option{
			Format: opt.Format,
			Report: opt.ReportFormat,
			Output: opt.Output,
		})
	}

	res := results.GetFailed()
	if opt.MisconfOptions.IncludeNonFailures {
		res = results
	}

	r := report.New(cloud.ProviderAWS, opt.Account, opt.Region, res, opt.Services)
	if err := report.Write(r, opt, cached); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	operation.Exit(opt, r.Failed())
	return nil
}
