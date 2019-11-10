package pkg

import (
	"context"
	l "log"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	dbFile "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/genuinetools/reg/registry"
	"github.com/urfave/cli"
	"golang.org/x/xerrors"
)

func Run(c *cli.Context) (err error) {
	if c.Bool("quiet") || c.Bool("no-progress") {
		utils.Quiet = true
	}
	debug := c.Bool("debug")
	if err = log.InitLogger(debug, c.Bool("quiet")); err != nil {
		l.Fatal(err)
	}

	cacheDir := c.String("cache-dir")
	utils.SetCacheDir(c.String("cache-dir"))
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if err = db.Init(cacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	downloadDBOnly := c.Bool("download-db-only")
	skipUpdate := c.Bool("skip-update")
	if skipUpdate && downloadDBOnly {
		return xerrors.New("The --skip-update and --download-db-only option can not be specified both")
	}

	light := c.Bool("light")
	if !skipUpdate {
		ctx := context.Background()
		client := dbFile.NewClient(ctx)
		if err = client.Download(ctx, c.App.Version, cacheDir, light); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
	}

	if downloadDBOnly {
		return nil
	}

	reset := c.Bool("reset")
	if reset {
		log.Logger.Info("Resetting...")
		if err = cache.Clear(); err != nil {
			return xerrors.New("failed to remove image layer cache")
		}
		if err = os.RemoveAll(utils.CacheDir()); err != nil {
			return xerrors.New("failed to remove cache")
		}
		return nil
	}

	clearCache := c.Bool("clear-cache")
	if clearCache {
		log.Logger.Info("Removing image caches...")
		if err = cache.Clear(); err != nil {
			return xerrors.New("failed to remove image layer cache")
		}
		return nil
	}

	args := c.Args()
	filePath := c.String("input")
	if filePath == "" && len(args) == 0 {
		log.Logger.Info(`trivy requires at least 1 argument or --input option.`)
		cli.ShowAppHelpAndExit(c, 1)
	}

	o := c.String("output")
	output := os.Stdout
	if o != "" {
		if output, err = os.Create(o); err != nil {
			return xerrors.Errorf("failed to create an output file: %w", err)
		}
	}

	var imageName string
	if filePath == "" {
		imageName = args[0]
	}

	// Check whether 'latest' tag is used
	if imageName != "" {
		image, err := registry.ParseImage(imageName)
		if err != nil {
			return xerrors.Errorf("invalid image: %w", err)
		}
		if image.Tag == "latest" && !clearCache {
			log.Logger.Warn("You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed")
		}
	}

	timeout := c.Duration("timeout")
	scanOptions := types.ScanOptions{
		VulnType: strings.Split(c.String("vuln-type"), ","),
		Timeout:  timeout,
	}

	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := scanner.ScanImage(imageName, filePath, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	severities := splitSeverity(c.String("severity"))
	ignoreFile := c.String("ignorefile")
	ignoreUnfixed := c.Bool("ignore-unfixed")
	vulnClient := vulnerability.NewClient()
	for i := range results {
		results[i].Vulnerabilities = vulnClient.FillAndFilter(results[i].Vulnerabilities,
			severities, ignoreUnfixed, ignoreFile, light)
	}

	format := c.String("format")
	template := c.String("template")
	if err = report.WriteResults(format, output, results, template, light); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exitCode := c.Int("exit-code")
	if exitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(exitCode)
			}
		}
	}

	return nil
}

func splitSeverity(severity string) []dbTypes.Severity {
	var severities []dbTypes.Severity
	for _, s := range strings.Split(severity, ",") {
		severity, err := dbTypes.NewSeverity(s)
		if err != nil {
			log.Logger.Warnf("unknown severity option: %s", err)
		}
		severities = append(severities, severity)
	}
	return severities
}
