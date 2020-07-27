package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/artifact"
	"github.com/aquasecurity/trivy/internal/client"
	"github.com/aquasecurity/trivy/internal/server"
	tdb "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

type VersionInfo struct {
	Version         string       `json:",omitempty"`
	VulnerabilityDB *db.Metadata `json:",omitempty"`
}

var (
	templateFlag = cli.StringFlag{
		Name:    "template",
		Aliases: []string{"t"},
		Value:   "",
		Usage:   "output template",
		EnvVars: []string{"TRIVY_TEMPLATE"},
	}

	formatFlag = cli.StringFlag{
		Name:    "format",
		Aliases: []string{"f"},
		Value:   "table",
		Usage:   "format (table, json, template)",
		EnvVars: []string{"TRIVY_FORMAT"},
	}

	inputFlag = cli.StringFlag{
		Name:    "input",
		Aliases: []string{"i"},
		Value:   "",
		Usage:   "input file path instead of image name",
		EnvVars: []string{"TRIVY_INPUT"},
	}

	severityFlag = cli.StringFlag{
		Name:    "severity",
		Aliases: []string{"s"},
		Value:   strings.Join(types.SeverityNames, ","),
		Usage:   "severities of vulnerabilities to be displayed (comma separated)",
		EnvVars: []string{"TRIVY_SEVERITY"},
	}

	outputFlag = cli.StringFlag{
		Name:    "output",
		Aliases: []string{"o"},
		Usage:   "output file name",
		EnvVars: []string{"TRIVY_OUTPUT"},
	}

	exitCodeFlag = cli.IntFlag{
		Name:    "exit-code",
		Usage:   "Exit code when vulnerabilities were found",
		Value:   0,
		EnvVars: []string{"TRIVY_EXIT_CODE"},
	}

	skipUpdateFlag = cli.BoolFlag{
		Name:    "skip-update",
		Usage:   "skip db update",
		EnvVars: []string{"TRIVY_SKIP_UPDATE"},
	}

	downloadDBOnlyFlag = cli.BoolFlag{
		Name:    "download-db-only",
		Usage:   "download/update vulnerability database but don't run a scan",
		EnvVars: []string{"TRIVY_DOWNLOAD_DB_ONLY"},
	}

	resetFlag = cli.BoolFlag{
		Name:    "reset",
		Usage:   "remove all caches and database",
		EnvVars: []string{"TRIVY_RESET"},
	}

	clearCacheFlag = cli.BoolFlag{
		Name:    "clear-cache",
		Aliases: []string{"c"},
		Usage:   "clear image caches without scanning",
		EnvVars: []string{"TRIVY_CLEAR_CACHE"},
	}

	quietFlag = cli.BoolFlag{
		Name:    "quiet",
		Aliases: []string{"q"},
		Usage:   "suppress progress bar and log output",
		EnvVars: []string{"TRIVY_QUIET"},
	}

	noProgressFlag = cli.BoolFlag{
		Name:    "no-progress",
		Usage:   "suppress progress bar",
		EnvVars: []string{"TRIVY_NO_PROGRESS"},
	}

	ignoreUnfixedFlag = cli.BoolFlag{
		Name:    "ignore-unfixed",
		Usage:   "display only fixed vulnerabilities",
		EnvVars: []string{"TRIVY_IGNORE_UNFIXED"},
	}

	debugFlag = cli.BoolFlag{
		Name:    "debug",
		Aliases: []string{"d"},
		Usage:   "debug mode",
		EnvVars: []string{"TRIVY_DEBUG"},
	}

	removedPkgsFlag = cli.BoolFlag{
		Name:    "removed-pkgs",
		Usage:   "detect vulnerabilities of removed packages (only for Alpine)",
		EnvVars: []string{"TRIVY_REMOVED_PKGS"},
	}

	vulnTypeFlag = cli.StringFlag{
		Name:    "vuln-type",
		Value:   "os,library",
		Usage:   "comma-separated list of vulnerability types (os,library)",
		EnvVars: []string{"TRIVY_VULN_TYPE"},
	}

	cacheDirFlag = cli.StringFlag{
		Name:    "cache-dir",
		Value:   utils.DefaultCacheDir(),
		Usage:   "cache directory",
		EnvVars: []string{"TRIVY_CACHE_DIR"},
	}

	ignoreFileFlag = cli.StringFlag{
		Name:    "ignorefile",
		Value:   vulnerability.DefaultIgnoreFile,
		Usage:   "specify .trivyignore file",
		EnvVars: []string{"TRIVY_IGNOREFILE"},
	}

	timeoutFlag = cli.DurationFlag{
		Name:    "timeout",
		Value:   time.Second * 120,
		Usage:   "docker timeout",
		EnvVars: []string{"TRIVY_TIMEOUT"},
	}

	lightFlag = cli.BoolFlag{
		Name:    "light",
		Usage:   "light mode: it's faster, but vulnerability descriptions and references are not displayed",
		EnvVars: []string{"TRIVY_LIGHT"},
	}

	token = cli.StringFlag{
		Name:    "token",
		Usage:   "for authentication",
		EnvVars: []string{"TRIVY_TOKEN"},
	}

	tokenHeader = cli.StringFlag{
		Name:    "token-header",
		Value:   "Trivy-Token",
		Usage:   "specify a header name for token",
		EnvVars: []string{"TRIVY_TOKEN_HEADER"},
	}

	ignorePolicy = cli.StringFlag{
		Name:    "ignore-policy",
		Usage:   "specify the Rego file to evaluate each vulnerability",
		EnvVars: []string{"TRIVY_IGNORE_POLICY"},
	}

	globalFlags = []cli.Flag{
		&quietFlag,
		&debugFlag,
		&cacheDirFlag,
	}

	imageFlags = []cli.Flag{
		&templateFlag,
		&formatFlag,
		&inputFlag,
		&severityFlag,
		&outputFlag,
		&exitCodeFlag,
		&skipUpdateFlag,
		&downloadDBOnlyFlag,
		&resetFlag,
		&clearCacheFlag,
		&noProgressFlag,
		&ignoreUnfixedFlag,
		&removedPkgsFlag,
		&vulnTypeFlag,
		&ignoreFileFlag,
		&timeoutFlag,
		&lightFlag,
		&ignorePolicy,
	}

	// deprecated options
	deprecatedFlags = []cli.Flag{
		&cli.StringFlag{
			Name:    "only-update",
			Usage:   "deprecated",
			EnvVars: []string{"TRIVY_ONLY_UPDATE"},
		},
		&cli.BoolFlag{
			Name:    "refresh",
			Usage:   "deprecated",
			EnvVars: []string{"TRIVY_REFRESH"},
		},
		&cli.BoolFlag{
			Name:    "auto-refresh",
			Usage:   "deprecated",
			EnvVars: []string{"TRIVY_AUTO_REFRESH"},
		},
	}
)

func NewApp(version string) *cli.App {
	cli.VersionPrinter = func(c *cli.Context) {
		showVersion(c.String("cache-dir"), c.String("format"), c.App.Version, c.App.Writer)
	}

	app := cli.NewApp()
	app.Name = "trivy"
	app.Version = version
	app.ArgsUsage = "target"
	app.Usage = "A simple and comprehensive vulnerability scanner for containers"
	app.EnableBashCompletion = true

	flags := append(globalFlags, setHidden(deprecatedFlags, true)...)
	flags = append(flags, setHidden(imageFlags, true)...)

	app.Flags = flags
	app.Commands = []*cli.Command{
		NewImageCommand(),
		NewFilesystemCommand(),
		NewRepositoryCommand(),
		NewClientCommand(),
		NewServerCommand(),
	}
	app.Action = artifact.ImageRun
	return app
}

func setHidden(flags []cli.Flag, hidden bool) []cli.Flag {
	var newFlags []cli.Flag
	for _, flag := range flags {
		var f cli.Flag
		switch pf := flag.(type) {
		case *cli.StringFlag:
			stringFlag := *pf
			stringFlag.Hidden = hidden
			f = &stringFlag
		case *cli.BoolFlag:
			boolFlag := *pf
			boolFlag.Hidden = hidden
			f = &boolFlag
		case *cli.IntFlag:
			intFlag := *pf
			intFlag.Hidden = hidden
			f = &intFlag
		case *cli.DurationFlag:
			durationFlag := *pf
			durationFlag.Hidden = hidden
			f = &durationFlag
		}
		newFlags = append(newFlags, f)
	}
	return newFlags
}

func showVersion(cacheDir, outputFormat, version string, outputWriter io.Writer) {
	var dbMeta *db.Metadata

	metadata, _ := tdb.NewMetadata(afero.NewOsFs(), cacheDir).Get()
	if !metadata.UpdatedAt.IsZero() && !metadata.NextUpdate.IsZero() && metadata.Version != 0 {
		dbMeta = &db.Metadata{
			Version:    metadata.Version,
			Type:       metadata.Type,
			NextUpdate: metadata.NextUpdate.UTC(),
			UpdatedAt:  metadata.UpdatedAt.UTC(),
		}
	}

	switch outputFormat {
	case "json":
		b, _ := json.Marshal(VersionInfo{
			Version:         version,
			VulnerabilityDB: dbMeta,
		})
		fmt.Fprintln(outputWriter, string(b))
	default:
		output := fmt.Sprintf("Version: %s\n", version)
		if dbMeta != nil {
			var dbType string
			switch dbMeta.Type {
			case 0:
				dbType = "Full"
			case 1:
				dbType = "Light"
			}
			output += fmt.Sprintf(`Vulnerability DB:
  Type: %s
  Version: %d
  UpdatedAt: %s
  NextUpdate: %s
`, dbType, dbMeta.Version, dbMeta.UpdatedAt.UTC(), dbMeta.NextUpdate.UTC())
		}
		fmt.Fprintf(outputWriter, output)
	}
}

func NewImageCommand() *cli.Command {
	return &cli.Command{
		Name:      "image",
		Aliases:   []string{"i"},
		ArgsUsage: "image_name",
		Usage:     "scan an image",
		Action:    artifact.ImageRun,
		Flags:     imageFlags,
	}
}

func NewFilesystemCommand() *cli.Command {
	return &cli.Command{
		Name:      "filesystem",
		Aliases:   []string{"fs"},
		ArgsUsage: "dir",
		Usage:     "scan local filesystem",
		Action:    artifact.FilesystemRun,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&inputFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&clearCacheFlag,
			&quietFlag,
			&ignoreUnfixedFlag,
			&debugFlag,
			&removedPkgsFlag,
			&vulnTypeFlag,
			&ignoreFileFlag,
			&cacheDirFlag,
			&timeoutFlag,
			&noProgressFlag,
			&ignorePolicy,
		},
	}
}

func NewRepositoryCommand() *cli.Command {
	return &cli.Command{
		Name:      "repository",
		Aliases:   []string{"repo"},
		ArgsUsage: "repo_url",
		Usage:     "scan remote repository",
		Action:    artifact.RepositoryRun,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&inputFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&clearCacheFlag,
			&quietFlag,
			&ignoreUnfixedFlag,
			&debugFlag,
			&removedPkgsFlag,
			&vulnTypeFlag,
			&ignoreFileFlag,
			&cacheDirFlag,
			&timeoutFlag,
			&noProgressFlag,
			&ignorePolicy,
		},
	}
}

func NewClientCommand() *cli.Command {
	return &cli.Command{
		Name:      "client",
		Aliases:   []string{"c"},
		ArgsUsage: "image_name",
		Usage:     "client mode",
		Action:    client.Run,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&inputFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&clearCacheFlag,
			&quietFlag,
			&ignoreUnfixedFlag,
			&debugFlag,
			&removedPkgsFlag,
			&vulnTypeFlag,
			&ignoreFileFlag,
			&cacheDirFlag,
			&timeoutFlag,
			&ignorePolicy,

			// original flags
			&token,
			&tokenHeader,
			&cli.StringFlag{
				Name:    "remote",
				Value:   "http://localhost:4954",
				Usage:   "server address",
				EnvVars: []string{"TRIVY_REMOTE"},
			},
			&cli.StringSliceFlag{
				Name:    "custom-headers",
				Usage:   "custom headers",
				EnvVars: []string{"TRIVY_CUSTOM_HEADERS"},
			},
		},
	}
}

func NewServerCommand() *cli.Command {
	return &cli.Command{
		Name:    "server",
		Aliases: []string{"s"},
		Usage:   "server mode",
		Action:  server.Run,
		Flags: []cli.Flag{
			&skipUpdateFlag,
			&downloadDBOnlyFlag,
			&resetFlag,
			&quietFlag,
			&debugFlag,
			&cacheDirFlag,

			// original flags
			&token,
			&tokenHeader,
			&cli.StringFlag{
				Name:    "listen",
				Value:   "localhost:4954",
				Usage:   "listen address",
				EnvVars: []string{"TRIVY_LISTEN"},
			},
		},
	}
}
