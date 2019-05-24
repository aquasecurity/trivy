package pkg

import (
	l "log"
	"os"
	"strings"

	"github.com/genuinetools/reg/registry"
	"github.com/knqyf263/fanal/cache"
	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"github.com/urfave/cli"
	"golang.org/x/xerrors"
)

func Run(c *cli.Context) (err error) {
	cliVersion := c.App.Version

	utils.Quiet = c.Bool("quiet")
	debug := c.Bool("debug")
	if err = log.InitLogger(debug); err != nil {
		l.Fatal(err)
	}

	cacheDir := c.String("cache-dir")
	if cacheDir != "" {
		utils.SetCacheDir(cacheDir)
	}

	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

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
	}

	refresh := c.Bool("refresh")
	args := c.Args()
	var noTarget bool
	filePath := c.String("input")
	if filePath == "" && len(args) == 0 {
		noTarget = true
		if !reset && !clearCache && !refresh {
			log.Logger.Info(`trivy" requires at least 1 argument or --input option.`)
			cli.ShowAppHelpAndExit(c, 1)
		}
	}

	autoRefresh := c.Bool("auto-refresh")
	skipUpdate := c.Bool("skip-update")
	onlyUpdate := c.String("only-update")
	if refresh || autoRefresh {
		if skipUpdate {
			return xerrors.New("The --skip-update option can not be specified with the --refresh or --auto-refresh option")
		}
		if onlyUpdate != "" {
			return xerrors.New("The --only-update option can not be specified with the --refresh or --auto-refresh option")
		}
	}
	if skipUpdate && onlyUpdate != "" {
		return xerrors.New("The --skip-update and --only-update option can not be specified both")
	}

	if err = db.Init(); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	needRefresh := false
	dbVersion := db.GetVersion()
	if dbVersion != "" && dbVersion != cliVersion {
		if !refresh && !autoRefresh {
			return xerrors.New("Detected version update of trivy. Please try again with --refresh or --auto-refresh option")
		}
		needRefresh = true
	}

	if refresh || needRefresh {
		log.Logger.Info("Refreshing DB...")
		if err = db.Reset(); err != nil {
			return xerrors.Errorf("error in refresh DB: %w", err)
		}
	}
	// this condition is already validated by skipUpdate && onlyUpdate != ""
	if onlyUpdate != "" {
		log.Logger.Warn("The --update-only option may cause the vulnerability details such as severity and title not to be displayed")
		if err = vulnsrc.Update(strings.Split(onlyUpdate, ",")); err != nil {
			return xerrors.Errorf("error in vulnerability DB update: %w", err)
		}
	} else {
		if err = vulnsrc.Update(vulnerability.DBNames); err != nil {
			return xerrors.Errorf("error in vulnerability DB update: %w", err)
		}
	}

	if err = db.SetVersion(cliVersion); err != nil {
		return xerrors.Errorf("unexpected error: %w", err)
	}

	// When specifying no image name and file name
	if noTarget {
		return nil
	}

	o := c.String("output")
	output := os.Stdout
	if o != "" {
		if output, err = os.Create(o); err != nil {
			return xerrors.Errorf("failed to create an output file: %w", err)
		}
	}

	var severities []vulnerability.Severity
	for _, s := range strings.Split(c.String("severity"), ",") {
		severity, err := vulnerability.NewSeverity(s)
		if err != nil {
			log.Logger.Infof("error in severity option: %s", err)
			cli.ShowAppHelpAndExit(c, 1)
		}
		severities = append(severities, severity)
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

	vulns, err := scanner.ScanImage(imageName, filePath)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	var results report.Results
	ignoreUnfixed := c.Bool("ignore-unfixed")
	for path, vuln := range vulns {
		results = append(results, report.Result{
			FileName:        path,
			Vulnerabilities: vulnerability.FillAndFilter(vuln, severities, ignoreUnfixed),
		})
	}

	var writer report.Writer
	switch format := c.String("format"); format {
	case "table":
		writer = &report.TableWriter{Output: output}
	case "json":
		writer = &report.JsonWriter{Output: output}
	default:
		return xerrors.Errorf("unknown format: %v", format)
	}

	if err = writer.Write(results); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
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
