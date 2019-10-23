package pkg

import (
	l "log"
	"os"
	"strings"
	"text/template"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnsrc"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"
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

	utils.SetCacheDir(c.String("cache-dir"))
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
			log.Logger.Info(`trivy requires at least 1 argument or --input option.`)
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
	if 0 < dbVersion && dbVersion < db.SchemaVersion {
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

	updateTargets := vulnsrc.UpdateList
	if onlyUpdate != "" {
		log.Logger.Warn("The --only-update option may cause the vulnerability details such as severity and title not to be displayed")
		updateTargets = strings.Split(onlyUpdate, ",")
	}

	if !skipUpdate {
		if err = vulnsrc.Update(updateTargets); err != nil {
			return xerrors.Errorf("error in vulnerability DB update: %w", err)
		}
	}

	dbc := db.Config{}
	if err = dbc.SetVersion(db.SchemaVersion); err != nil {
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

	ignoreFile := c.String("ignorefile")

	ignoreUnfixed := c.Bool("ignore-unfixed")
	for i := range results {
		results[i].Vulnerabilities = vulnerability.FillAndFilter(results[i].Vulnerabilities, severities, ignoreUnfixed, ignoreFile)
	}

	var writer report.Writer
	switch format := c.String("format"); format {
	case "table":
		writer = &report.TableWriter{Output: output}
	case "json":
		writer = &report.JsonWriter{Output: output}
	case "template":
		outputTemplate := c.String("template")
		tmpl, err := template.New("output template").Parse(outputTemplate)
		if err != nil {
			return xerrors.Errorf("error parsing template: %w", err)
		}
		writer = &report.TemplateWriter{Output: output, Template: tmpl}
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
