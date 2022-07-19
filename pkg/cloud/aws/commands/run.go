package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"

	"github.com/aquasecurity/trivy/pkg/cloud"

	"github.com/aquasecurity/trivy/pkg/cloud/cache"

	"github.com/aquasecurity/trivy/pkg/flag"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/aquasecurity/trivy/pkg/cloud/aws/scanner"
	"github.com/aquasecurity/trivy/pkg/cloud/report"

	"github.com/aquasecurity/trivy/pkg/log"

	awsScanner "github.com/aquasecurity/defsec/pkg/scanners/cloud/aws"
)

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
		return "", "", fmt.Errorf("failed to discover AWS caller identity: %w", err)
	}
	if result.Account == nil {
		return "", "", fmt.Errorf("missing account id for aws account")
	}
	log.Logger.Debugf("Verified AWS credentials for account %s!", *result.Account)
	return *result.Account, cfg.Region, nil
}

func Run(ctx context.Context, opt flag.Options) error {

	ctx, cancel := context.WithTimeout(ctx, opt.GlobalOptions.Timeout)
	defer cancel()

	if err := log.InitLogger(opt.Debug, false); err != nil {
		return fmt.Errorf("logger error: %w", err)
	}

	var err error
	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	reportOptions := report.Option{
		Format:      opt.Format,
		Output:      opt.Output,
		Severities:  opt.Severities,
		ReportLevel: report.LevelService,
	}
	if len(opt.Services) == 1 {
		reportOptions.ReportLevel = report.LevelResource
		reportOptions.Service = opt.Services[0]
		if opt.ARN != "" {
			reportOptions.ReportLevel = report.LevelResult
			reportOptions.ARN = opt.ARN
		}
	} else if opt.ARN != "" {
		return fmt.Errorf("you must specify the single --service which the --arn relates to")
	}

	accountID := opt.Account
	region := opt.Region
	if accountID == "" || region == "" {
		accountID, region, err = getAccountIDAndRegion(ctx, opt.Region)
		if err != nil {
			return err
		}
	}

	allSelectedServices := opt.Services

	if len(allSelectedServices) == 0 {
		log.Logger.Debug("No service(s) specified, scanning all services...")
		allSelectedServices = awsScanner.AllSupportedServices()
	} else {
		log.Logger.Debugf("Specific services were requested: [%s]...", strings.Join(allSelectedServices, ", "))
		for _, service := range allSelectedServices {
			var found bool
			supported := awsScanner.AllSupportedServices()
			for _, allowed := range supported {
				if allowed == service {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("service '%s' is not currently supported - supported services are: %s", service, strings.Join(supported, ", "))
			}
		}
	}

	cached := cache.New(opt.CacheDir, cloud.ProviderAWS, accountID, region)
	servicesInCache := cached.ListAvailableServices()
	var servicesToLoadFromCache []string
	var servicesToScan []string
	for _, service := range allSelectedServices {
		if cached != nil {
			var inCache bool
			for _, cacheSvc := range servicesInCache {
				if cacheSvc == service {
					log.Logger.Debugf("Results for service '%s' found in cache.", service)
					inCache = true
					break
				}
			}
			if inCache && !opt.UpdateCache {
				servicesToLoadFromCache = append(servicesToLoadFromCache, service)
				continue
			}
		}
		servicesToScan = append(servicesToScan, service)
	}

	var r *report.Report

	// if there is anything we need that wasn't in the cache, scan it now
	if len(servicesToScan) > 0 {
		log.Logger.Debugf("Scanning the following services using the AWS API: [%s]...", strings.Join(servicesToScan, ", "))
		opt.Services = servicesToScan
		results, err := scanner.NewScanner().Scan(ctx, opt)
		if err != nil {
			return fmt.Errorf("aws scan error: %w", err)
		}
		r = report.New(cloud.ProviderAWS, accountID, region, results.GetFailed(), allSelectedServices)
	} else {
		log.Logger.Debug("No more services to scan - everything was found in the cache.")
		r = report.New(cloud.ProviderAWS, accountID, region, nil, allSelectedServices)
	}
	if len(servicesToLoadFromCache) > 0 {
		log.Logger.Debug("Loading cached results...")
		cachedReport, err := cached.LoadReport(servicesToLoadFromCache...)
		if err != nil {
			return err
		}
		for service, results := range cachedReport.Results {
			r.AddResultForService(service, results.Result, results.CreationTime)
		}
		reportOptions.FromCache = true
	}

	if len(servicesToScan) > 0 { // don't write cache if we didn't scan anything new
		log.Logger.Debugf("Writing results to cache for services [%s]...", strings.Join(r.ServicesInScope, ", "))
		if err := cached.Save(r); err != nil {
			return err
		}
	}

	log.Logger.Debug("Writing report to output...")
	if err := report.Write(r, reportOptions); err != nil {
		return fmt.Errorf("unable to write results: %w", err)
	}

	cmd.Exit(opt, r.Failed())
	return nil
}
