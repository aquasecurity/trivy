package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	awsScanner "github.com/aquasecurity/defsec/pkg/scanners/cloud/aws"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	javadb "github.com/aquasecurity/trivy-java-db/pkg/db"
	awscommands "github.com/aquasecurity/trivy/pkg/cloud/aws/commands"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/server"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/flag"
	k8scommands "github.com/aquasecurity/trivy/pkg/k8s/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/module"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/types"
)

// VersionInfo holds the trivy DB version Info
type VersionInfo struct {
	Version         string             `json:",omitempty"`
	VulnerabilityDB *metadata.Metadata `json:",omitempty"`
	JavaDB          *metadata.Metadata `json:",omitempty"`
	PolicyBundle    *policy.Metadata   `json:",omitempty"`
}

const (
	usageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

%s

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
)

var (
	outputWriter io.Writer = os.Stdout
)

// SetOut overrides the destination for messages
func SetOut(out io.Writer) {
	outputWriter = out
}

// NewApp is the factory method to return Trivy CLI
func NewApp(version string) *cobra.Command {
	globalFlags := flag.NewGlobalFlagGroup()
	rootCmd := NewRootCommand(version, globalFlags)
	rootCmd.AddCommand(
		NewImageCommand(globalFlags),
		NewFilesystemCommand(globalFlags),
		NewRootfsCommand(globalFlags),
		NewRepositoryCommand(globalFlags),
		NewClientCommand(globalFlags),
		NewServerCommand(globalFlags),
		NewConfigCommand(globalFlags),
		NewPluginCommand(),
		NewModuleCommand(globalFlags),
		NewKubernetesCommand(globalFlags),
		NewSBOMCommand(globalFlags),
		NewVersionCommand(globalFlags),
		NewAWSCommand(globalFlags),
		NewVMCommand(globalFlags),
	)
	rootCmd.AddCommand(loadPluginCommands()...)

	return rootCmd
}

func loadPluginCommands() []*cobra.Command {
	var commands []*cobra.Command
	plugins, err := plugin.LoadAll()
	if err != nil {
		log.Logger.Debugf("no plugins were loaded")
		return nil
	}
	for _, p := range plugins {
		p := p
		cmd := &cobra.Command{
			Use:   fmt.Sprintf("%s [flags]", p.Name),
			Short: p.Usage,
			RunE: func(cmd *cobra.Command, args []string) error {
				if err = p.Run(cmd.Context(), args); err != nil {
					return xerrors.Errorf("plugin error: %w", err)
				}
				return nil
			},
			DisableFlagParsing: true,
		}
		commands = append(commands, cmd)
	}
	return commands
}

func initConfig(configFile string) error {
	// Read from config
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Logger.Debugf("config file %q not found", configFile)
			return nil
		}
		return xerrors.Errorf("config file %q loading error: %s", configFile, err)
	}
	log.Logger.Infof("Loaded %s", configFile)
	return nil
}

func NewRootCommand(version string, globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	var versionFormat string
	cmd := &cobra.Command{
		Use:   "trivy [global flags] command [flags] target",
		Short: "Unified security scanner",
		Long:  "Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues and hard-coded secrets",
		Example: `  # Scan a container image
  $ trivy image python:3.4-alpine

  # Scan a container image from a tar archive
  $ trivy image --input ruby-3.1.tar

  # Scan local filesystem
  $ trivy fs .

  # Run in server mode
  $ trivy server`,
		Args: cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cmd.SetOut(outputWriter)

			// Set the Trivy version here so that we can override version printer.
			cmd.Version = version

			// viper.BindPFlag cannot be called in init().
			// cf. https://github.com/spf13/cobra/issues/875
			//     https://github.com/spf13/viper/issues/233
			if err := globalFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}

			// The config path is needed for config initialization.
			// It needs to be obtained before ToOptions().
			configPath := viper.GetString(flag.ConfigFileFlag.ConfigName)

			// Configure environment variables and config file
			// It cannot be called in init() because it must be called after viper.BindPFlags.
			if err := initConfig(configPath); err != nil {
				return err
			}

			globalOptions := globalFlags.ToOptions()

			// Initialize logger
			if err := log.InitLogger(globalOptions.Debug, globalOptions.Quiet); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			globalOptions := globalFlags.ToOptions()
			if globalOptions.ShowVersion {
				// Customize version output
				showVersion(globalOptions.CacheDir, versionFormat, version, outputWriter)
			} else {
				return cmd.Help()
			}
			return nil
		},
	}

	// Add version format flag, only json is supported
	cmd.Flags().StringVarP(&versionFormat, flag.FormatFlag.Name, flag.FormatFlag.Shorthand, "", "version format (json)")

	globalFlags.AddFlags(cmd)

	return cmd
}

func NewImageCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()

	report := flag.ReportFormatFlag
	report.Value = "summary"                                     // override the default value as the summary is preferred for the compliance report
	report.Usage = "specify a format for the compliance report." // "--report" works only with "--compliance"
	reportFlagGroup.ReportFormat = &report

	compliance := flag.ComplianceFlag
	compliance.Usage += fmt.Sprintf(" (%s)", types.ComplianceDockerCIS)
	reportFlagGroup.Compliance = &compliance // override usage as the accepted values differ for each subcommand.

	imageFlags := &flag.Flags{
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		ImageFlagGroup:         flag.NewImageFlagGroup(), // container image specific
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:     "image [flags] IMAGE_NAME",
		Aliases: []string{"i"},
		Short:   "Scan a container image",
		Example: `  # Scan a container image
  $ trivy image python:3.4-alpine

  # Scan a container image from a tar archive
  $ trivy image --input ruby-3.1.tar

  # Filter by severities
  $ trivy image --severity HIGH,CRITICAL alpine:3.15

  # Ignore unfixed/unpatched vulnerabilities
  $ trivy image --ignore-unfixed alpine:3.15

  # Scan a container image in client mode
  $ trivy image --server http://127.0.0.1:4954 alpine:latest

  # Generate json result
  $ trivy image --format json --output result.json alpine:3.15

  # Generate a report in the CycloneDX format
  $ trivy image --format cyclonedx --output result.cdx alpine:3.15`,

		// 'Args' cannot be used since it is called before PreRunE and viper is not configured yet.
		// cmd.Args     -> cannot validate args here
		// cmd.PreRunE  -> configure viper && validate args
		// cmd.RunE     -> run the command
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// viper.BindPFlag cannot be called in init(), so it is called in PreRunE.
			// cf. https://github.com/spf13/cobra/issues/875
			//     https://github.com/spf13/viper/issues/233
			if err := imageFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := imageFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetContainerImage)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	imageFlags.AddFlags(cmd)
	cmd.SetFlagErrorFunc(flagErrorFunc)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, imageFlags.Usages(cmd)))

	return cmd
}

func NewFilesystemCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFlagGroup.ReportFormat = nil // TODO: support --report summary
	reportFlagGroup.Compliance = nil   // disable '--compliance'
	reportFlagGroup.ExitOnEOL = nil    // disable '--exit-on-eol'

	fsFlags := &flag.Flags{
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:     "filesystem [flags] PATH",
		Aliases: []string{"fs"},
		Short:   "Scan local filesystem",
		Example: `  # Scan a local project including language-specific files
  $ trivy fs /path/to/your_project

  # Scan a single file
  $ trivy fs ./trivy-ci-test/Pipfile.lock`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := fsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := fsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := fsFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetFilesystem)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.SetFlagErrorFunc(flagErrorFunc)
	fsFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, fsFlags.Usages(cmd)))

	return cmd
}

func NewRootfsCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFlagGroup.ReportFormat = nil // TODO: support --report summary
	reportFlagGroup.Compliance = nil   // disable '--compliance'

	rootfsFlags := &flag.Flags{
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:   "rootfs [flags] ROOTDIR",
		Short: "Scan rootfs",
		Example: `  # Scan unpacked filesystem
  $ docker export $(docker create alpine:3.10.2) | tar -C /tmp/rootfs -xvf -
  $ trivy rootfs /tmp/rootfs

  # Scan from inside a container
  $ docker run --rm -it alpine:3.11
  / # curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  / # trivy rootfs /`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := rootfsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := rootfsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := rootfsFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetRootfs)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	rootfsFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, rootfsFlags.Usages(cmd)))

	return cmd
}

func NewRepositoryCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFlagGroup.ReportFormat = nil // TODO: support --report summary
	reportFlagGroup.Compliance = nil   // disable '--compliance'
	reportFlagGroup.ExitOnEOL = nil    // disable '--exit-on-eol'

	repoFlags := &flag.Flags{
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
		RepoFlagGroup:          flag.NewRepoFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:     "repository [flags] REPO_URL",
		Aliases: []string{"repo"},
		Short:   "Scan a remote repository",
		Example: `  # Scan your remote git repository
  $ trivy repo https://github.com/knqyf263/trivy-ci-test`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := repoFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := repoFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := repoFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetRepository)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	repoFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, repoFlags.Usages(cmd)))

	return cmd
}

// NewClientCommand returns the 'client' subcommand that is deprecated
func NewClientCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	remoteFlags := flag.NewClientFlags()
	remoteAddr := flag.Flag{
		Name:       "remote",
		ConfigName: "server.addr",
		Shorthand:  "",
		Value:      "http://localhost:4954",
		Usage:      "server address",
	}
	remoteFlags.ServerAddr = &remoteAddr // disable '--server' and enable '--remote' instead.

	clientFlags := &flag.Flags{
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		RemoteFlagGroup:        remoteFlags,
		ReportFlagGroup:        flag.NewReportFlagGroup(),
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:     "client [flags] IMAGE_NAME",
		Aliases: []string{"c"},
		Hidden:  true, // 'client' command is deprecated
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := clientFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Logger.Warn("'client' subcommand is deprecated now. See https://github.com/aquasecurity/trivy/discussions/2119")

			if err := clientFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := clientFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetContainerImage)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	clientFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, clientFlags.Usages(cmd)))

	return cmd
}

func NewServerCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	serverFlags := &flag.Flags{
		CacheFlagGroup:  flag.NewCacheFlagGroup(),
		DBFlagGroup:     flag.NewDBFlagGroup(),
		ModuleFlagGroup: flag.NewModuleFlagGroup(),
		RemoteFlagGroup: flag.NewServerFlags(),
	}

	cmd := &cobra.Command{
		Use:     "server [flags]",
		Aliases: []string{"s"},
		Short:   "Server mode",
		Example: `  # Run a server
  $ trivy server

  # Listen on 0.0.0.0:10000
  $ trivy server --listen 0.0.0.0:10000
`,
		Args: cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := serverFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := serverFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return server.Run(cmd.Context(), options)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	serverFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, serverFlags.Usages(cmd)))

	return cmd
}

func NewConfigCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFlagGroup.DependencyTree = nil // disable '--dependency-tree'
	reportFlagGroup.IgnorePolicy = nil   // disable '--ignore-policy'
	reportFlagGroup.ListAllPkgs = nil    // disable '--list-all-pkgs'
	reportFlagGroup.ReportFormat = nil   // TODO: support --report summary
	reportFlagGroup.Compliance = nil     // disable '--compliance'
	reportFlagGroup.ExitOnEOL = nil      // disable '--exit-on-eol'

	scanFlags := &flag.ScanFlagGroup{
		// Enable only '--skip-dirs' and '--skip-files' and disable other flags
		SkipDirs:     &flag.SkipDirsFlag,
		SkipFiles:    &flag.SkipFilesFlag,
		FilePatterns: &flag.FilePatternsFlag,
	}

	configFlags := &flag.Flags{
		CacheFlagGroup:    flag.NewCacheFlagGroup(),
		MisconfFlagGroup:  flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:   flag.NewModuleFlagGroup(),
		RegistryFlagGroup: flag.NewRegistryFlagGroup(),
		RegoFlagGroup:     flag.NewRegoFlagGroup(),
		K8sFlagGroup: &flag.K8sFlagGroup{
			// disable unneeded flags
			K8sVersion: &flag.K8sVersionFlag,
		},
		ReportFlagGroup: reportFlagGroup,
		ScanFlagGroup:   scanFlags,
	}

	cmd := &cobra.Command{
		Use:     "config [flags] DIR",
		Aliases: []string{"conf"},
		Short:   "Scan config files for misconfigurations",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := configFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := configFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := configFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			// Disable OS and language analyzers
			options.DisabledAnalyzers = append(analyzer.TypeOSes, analyzer.TypeLanguages...)

			// Scan only for misconfigurations
			options.Scanners = types.Scanners{types.MisconfigScanner}

			return artifact.Run(cmd.Context(), options, artifact.TargetFilesystem)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	configFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, configFlags.Usages(cmd)))

	return cmd
}

func NewPluginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "plugin subcommand",
		Aliases:       []string{"p"},
		Short:         "Manage plugins",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:                   "install URL | FILE_PATH",
			Aliases:               []string{"i"},
			Short:                 "Install a plugin",
			SilenceErrors:         true,
			DisableFlagsInUseLine: true,
			Args:                  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if _, err := plugin.Install(cmd.Context(), args[0], true); err != nil {
					return xerrors.Errorf("plugin install error: %w", err)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:                   "uninstall PLUGIN_NAME",
			Aliases:               []string{"u"},
			SilenceErrors:         true,
			DisableFlagsInUseLine: true,
			Short:                 "Uninstall a plugin",
			Args:                  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				if err := plugin.Uninstall(args[0]); err != nil {
					return xerrors.Errorf("plugin uninstall error: %w", err)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:                   "list",
			Aliases:               []string{"l"},
			SilenceErrors:         true,
			DisableFlagsInUseLine: true,
			Short:                 "List installed plugin",
			Args:                  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				info, err := plugin.List()
				if err != nil {
					return xerrors.Errorf("plugin list display error: %w", err)
				}
				if _, err = fmt.Fprintf(os.Stdout, info); err != nil {
					return xerrors.Errorf("print error: %w", err)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:                   "info PLUGIN_NAME",
			Short:                 "Show information about the specified plugin",
			SilenceErrors:         true,
			DisableFlagsInUseLine: true,
			Args:                  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				info, err := plugin.Information(args[0])
				if err != nil {
					return xerrors.Errorf("plugin information display error: %w", err)
				}
				if _, err = fmt.Fprintf(os.Stdout, info); err != nil {
					return xerrors.Errorf("print error: %w", err)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:                   "run URL | FILE_PATH",
			Aliases:               []string{"r"},
			SilenceErrors:         true,
			DisableFlagsInUseLine: true,
			Short:                 "Run a plugin on the fly",
			Args:                  cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return plugin.RunWithArgs(cmd.Context(), args[0], args[1:])
			},
		},
		&cobra.Command{
			Use:                   "update PLUGIN_NAME",
			Short:                 "Update an existing plugin",
			SilenceErrors:         true,
			DisableFlagsInUseLine: true,
			Args:                  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				if err := plugin.Update(args[0]); err != nil {
					return xerrors.Errorf("plugin update error: %w", err)
				}
				return nil
			},
		},
	)
	cmd.SetFlagErrorFunc(flagErrorFunc)
	return cmd
}

func NewModuleCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	moduleFlags := &flag.Flags{
		ModuleFlagGroup: flag.NewModuleFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:           "module subcommand",
		Aliases:       []string{"m"},
		Short:         "Manage modules",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	// Add subcommands
	cmd.AddCommand(
		&cobra.Command{
			Use:     "install [flags] REPOSITORY",
			Aliases: []string{"i"},
			Short:   "Install a module",
			Args:    cobra.ExactArgs(1),
			PreRunE: func(cmd *cobra.Command, args []string) error {
				if err := moduleFlags.Bind(cmd); err != nil {
					return xerrors.Errorf("flag bind error: %w", err)
				}
				return nil
			},
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 1 {
					return cmd.Help()
				}

				repo := args[0]
				opts, err := moduleFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
				if err != nil {
					return xerrors.Errorf("flag error: %w", err)
				}
				return module.Install(cmd.Context(), opts.ModuleDir, repo, opts.Quiet, opts.Remote())
			},
		},
		&cobra.Command{
			Use:     "uninstall [flags] REPOSITORY",
			Aliases: []string{"u"},
			Short:   "Uninstall a module",
			Args:    cobra.ExactArgs(1),
			PreRunE: func(cmd *cobra.Command, args []string) error {
				if err := moduleFlags.Bind(cmd); err != nil {
					return xerrors.Errorf("flag bind error: %w", err)
				}
				return nil
			},
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 1 {
					return cmd.Help()
				}

				repo := args[0]
				opts, err := moduleFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
				if err != nil {
					return xerrors.Errorf("flag error: %w", err)
				}
				return module.Uninstall(cmd.Context(), opts.ModuleDir, repo)
			},
		},
	)
	moduleFlags.AddFlags(cmd)
	cmd.SetFlagErrorFunc(flagErrorFunc)
	return cmd
}

func NewKubernetesCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	scanFlags := flag.NewScanFlagGroup()
	scanners := flag.ScannersFlag
	scanners.Value = fmt.Sprintf( // overwrite the default value
		"%s,%s,%s,%s",
		types.VulnerabilityScanner,
		types.MisconfigScanner,
		types.SecretScanner,
		types.RBACScanner,
	)
	scanFlags.Scanners = &scanners

	reportFlagGroup := flag.NewReportFlagGroup()
	compliance := flag.ComplianceFlag
	compliance.Usage += fmt.Sprintf(" (%s,%s, %s, %s)", types.ComplianceK8sNsa, types.ComplianceK8sCIS, types.ComplianceK8sPSSBaseline, types.ComplianceK8sPSSRestricted)
	reportFlagGroup.Compliance = &compliance // override usage as the accepted values differ for each subcommand.
	reportFlagGroup.ExitOnEOL = nil          // disable '--exit-on-eol'

	k8sFlags := &flag.Flags{
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		K8sFlagGroup:           flag.NewK8sFlagGroup(), // kubernetes-specific flags
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          scanFlags,
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}
	cmd := &cobra.Command{
		Use:     "kubernetes [flags] { cluster | all | specific resources like kubectl. eg: pods, pod/NAME }",
		Aliases: []string{"k8s"},
		Short:   "[EXPERIMENTAL] Scan kubernetes cluster",
		Example: `  # cluster scanning
  $ trivy k8s --report summary cluster

  # namespace scanning:
  $ trivy k8s -n kube-system --report summary all

  # resources scanning:
  $ trivy k8s --report=summary deploy
  $ trivy k8s --namespace=kube-system --report=summary deploy,configmaps

  # resource scanning:
  $ trivy k8s deployment/orion
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := k8sFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := k8sFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			opts, err := k8sFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			return k8scommands.Run(cmd.Context(), args, opts)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	k8sFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, k8sFlags.Usages(cmd)))

	return cmd
}

func NewAWSCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	compliance := flag.ComplianceFlag
	compliance.Usage += fmt.Sprintf(" (%s, %s)", types.ComplianceAWSCIS12, types.ComplianceAWSCIS14)
	reportFlagGroup.Compliance = &compliance // override usage as the accepted values differ for each subcommand.
	reportFlagGroup.ExitOnEOL = nil          // disable '--exit-on-eol'

	awsFlags := &flag.Flags{
		AWSFlagGroup:     flag.NewAWSFlagGroup(),
		CloudFlagGroup:   flag.NewCloudFlagGroup(),
		MisconfFlagGroup: flag.NewMisconfFlagGroup(),
		RegoFlagGroup:    flag.NewRegoFlagGroup(),
		ReportFlagGroup:  reportFlagGroup,
	}

	services := awsScanner.AllSupportedServices()

	cmd := &cobra.Command{
		Use:     "aws [flags]",
		Aliases: []string{},
		Args:    cobra.ExactArgs(0),
		Short:   "[EXPERIMENTAL] Scan AWS account",
		Long: fmt.Sprintf(`Scan an AWS account for misconfigurations. Trivy uses the same authentication methods as the AWS CLI. See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html

The following services are supported:
- %s
`, strings.Join(services, "\n- ")),
		Example: `  # basic scanning
  $ trivy aws --region us-east-1

  # limit scan to a single service:
  $ trivy aws --region us-east-1 --service s3

  # limit scan to multiple services:
  $ trivy aws --region us-east-1 --service s3 --service ec2

  # force refresh of cache for fresh results
  $ trivy aws --region us-east-1 --update-cache
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := awsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := awsFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			if opts.Timeout < time.Hour {
				opts.Timeout = time.Hour
				log.Logger.Debug("Timeout is set to less than 1 hour - upgrading to 1 hour for this command.")
			}
			return awscommands.Run(cmd.Context(), opts)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	awsFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, awsFlags.Usages(cmd)))

	return cmd
}

func NewVMCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFlagGroup.ReportFormat = nil // TODO: support --report summary

	vmFlags := &flag.Flags{
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
		AWSFlagGroup: &flag.AWSFlagGroup{
			Region: &flag.Flag{
				Name:       "aws-region",
				ConfigName: "aws.region",
				Value:      "",
				Usage:      "AWS region to scan",
			},
		},
	}

	cmd := &cobra.Command{
		Use:     "vm [flags] VM_IMAGE",
		Aliases: []string{},
		Short:   "[EXPERIMENTAL] Scan a virtual machine image",
		Example: `  # Scan your AWS AMI
  $ trivy vm --scanners vuln ami:${your_ami_id}

  # Scan your AWS EBS snapshot
  $ trivy vm ebs:${your_ebs_snapshot_id}
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := vmFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := vmFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := vmFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			if options.Timeout < time.Minute*30 {
				options.Timeout = time.Minute * 30
				log.Logger.Debug("Timeout is set to less than 30 min - upgrading to 30 min for this command.")
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetVM)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	vmFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, vmFlags.Usages(cmd)))

	return cmd
}

func NewSBOMCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFlagGroup.DependencyTree = nil // disable '--dependency-tree'
	reportFlagGroup.ReportFormat = nil   // TODO: support --report summary

	scanFlags := flag.NewScanFlagGroup()
	scanFlags.Scanners = nil // disable '--scanners' as it always scans for vulnerabilities

	sbomFlags := &flag.Flags{
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SBOMFlagGroup:          flag.NewSBOMFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:   "sbom [flags] SBOM_PATH",
		Short: "Scan SBOM for vulnerabilities",
		Example: `  # Scan CycloneDX and show the result in tables
  $ trivy sbom /path/to/report.cdx

  # Scan CycloneDX and generate a CycloneDX report
  $ trivy sbom --format cyclonedx /path/to/report.cdx

  # Scan CycloneDX-type attestation and show the result in tables
  $ trivy sbom /path/to/report.cdx.intoto.jsonl
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := sbomFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := sbomFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := sbomFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			// Scan vulnerabilities
			options.Scanners = types.Scanners{types.VulnerabilityScanner}

			return artifact.Run(cmd.Context(), options, artifact.TargetSBOM)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	sbomFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, sbomFlags.Usages(cmd)))

	return cmd
}

func NewVersionCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	var versionFormat string
	cmd := &cobra.Command{
		Use:   "version [flags]",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options := globalFlags.ToOptions()
			showVersion(options.CacheDir, versionFormat, cmd.Version, outputWriter)

			return nil
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)

	// Add version format flag, only json is supported
	cmd.Flags().StringVarP(&versionFormat, flag.FormatFlag.Name, flag.FormatFlag.Shorthand, "", "version format (json)")

	return cmd
}

func showVersion(cacheDir, outputFormat, version string, outputWriter io.Writer) {
	var dbMeta *metadata.Metadata
	var javadbMeta *metadata.Metadata

	mc := metadata.NewClient(cacheDir)
	meta, _ := mc.Get() // nolint: errcheck
	if !meta.UpdatedAt.IsZero() && !meta.NextUpdate.IsZero() && meta.Version != 0 {
		dbMeta = &metadata.Metadata{
			Version:      meta.Version,
			NextUpdate:   meta.NextUpdate.UTC(),
			UpdatedAt:    meta.UpdatedAt.UTC(),
			DownloadedAt: meta.DownloadedAt.UTC(),
		}
	}

	mcJava := javadb.NewMetadata(filepath.Join(cacheDir, "java-db"))
	metaJava, _ := mcJava.Get() // nolint: errcheck
	if !metaJava.UpdatedAt.IsZero() && !metaJava.NextUpdate.IsZero() && metaJava.Version != 0 {
		javadbMeta = &metadata.Metadata{
			Version:      metaJava.Version,
			NextUpdate:   metaJava.NextUpdate.UTC(),
			UpdatedAt:    metaJava.UpdatedAt.UTC(),
			DownloadedAt: metaJava.DownloadedAt.UTC(),
		}
	}

	var pbMeta *policy.Metadata
	pc, err := policy.NewClient(cacheDir, false)
	if pc != nil && err == nil {
		pbMeta, _ = pc.GetMetadata()
	}

	switch outputFormat {
	case "json":
		b, _ := json.Marshal(VersionInfo{
			Version:         version,
			VulnerabilityDB: dbMeta,
			JavaDB:          javadbMeta,
			PolicyBundle:    pbMeta,
		})
		fmt.Fprintln(outputWriter, string(b))
	default:
		output := fmt.Sprintf("Version: %s\n", version)
		if dbMeta != nil {
			output += fmt.Sprintf(`Vulnerability DB:
  Version: %d
  UpdatedAt: %s
  NextUpdate: %s
  DownloadedAt: %s
`, dbMeta.Version, dbMeta.UpdatedAt.UTC(), dbMeta.NextUpdate.UTC(), dbMeta.DownloadedAt.UTC())
		}

		if javadbMeta != nil {
			output += fmt.Sprintf(`Java DB:
  Version: %d
  UpdatedAt: %s
  NextUpdate: %s
  DownloadedAt: %s
`, javadbMeta.Version, javadbMeta.UpdatedAt.UTC(), javadbMeta.NextUpdate.UTC(), javadbMeta.DownloadedAt.UTC())
		}

		if pbMeta != nil {
			output += fmt.Sprintf(`Policy Bundle:
  Digest: %s
  DownloadedAt: %s
`, pbMeta.Digest, pbMeta.DownloadedAt.UTC())
		}
		fmt.Fprintf(outputWriter, output)
	}
}

func validateArgs(cmd *cobra.Command, args []string) error {
	// '--clear-cache', '--download-db-only', '--download-java-db-only', '--reset' and '--generate-default-config' don't conduct the subsequent scanning
	if viper.GetBool(flag.ClearCacheFlag.ConfigName) || viper.GetBool(flag.DownloadDBOnlyFlag.ConfigName) ||
		viper.GetBool(flag.ResetFlag.ConfigName) || viper.GetBool(flag.GenerateDefaultConfigFlag.ConfigName) ||
		viper.GetBool(flag.DownloadJavaDBOnlyFlag.ConfigName) {
		return nil
	}

	if len(args) == 0 && viper.GetString(flag.InputFlag.ConfigName) == "" {
		if err := cmd.Help(); err != nil {
			return err
		}

		if f := cmd.Flags().Lookup(flag.InputFlag.ConfigName); f != nil {
			return xerrors.New(`Require at least 1 argument or --input option`)
		}
		return xerrors.New(`Require at least 1 argument`)
	} else if cmd.Name() != "kubernetes" && len(args) > 1 {
		if err := cmd.Help(); err != nil {
			return err
		}
		return xerrors.New(`multiple targets cannot be specified`)
	}

	return nil
}

// show help on using the command when an invalid flag is encountered
func flagErrorFunc(command *cobra.Command, err error) error {
	if err := command.Help(); err != nil {
		return err
	}
	command.Println() //add empty line after list of flags
	return err
}
