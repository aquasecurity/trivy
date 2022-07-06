package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"

	k8scommands "github.com/aquasecurity/trivy/pkg/k8s/commands"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/plugin"
	"github.com/aquasecurity/trivy/pkg/commands/server"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/module"
	"github.com/aquasecurity/trivy/pkg/types"
)

// VersionInfo holds the trivy DB version Info
type VersionInfo struct {
	Version         string             `json:",omitempty"`
	VulnerabilityDB *metadata.Metadata `json:",omitempty"`
}

var (
	outputWriter io.Writer = os.Stdout
)

// SetOut overrides the destination for messages
func SetOut(out io.Writer) {
	outputWriter = out
}

// NewApp is the factory method to return Trivy CLI
func NewApp(version string) *cobra.Command {
	cobra.OnInitialize(initConfig)

	globalFlags := flag.NewGlobalDefaultFlags()
	rootCmd := NewRootCommand(version, globalFlags)

	if runAsPlugin := os.Getenv("TRIVY_RUN_AS_PLUGIN"); runAsPlugin != "" {
		rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
			return plugin.RunWithArgs(cmd.Context(), runAsPlugin, args)
		}
		rootCmd.DisableFlagParsing = true
		return rootCmd
	}

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
	)
	rootCmd.AddCommand(plugin.LoadCommands()...)

	return rootCmd
}

func initConfig() {
	// Configure environment variables
	viper.SetEnvPrefix("trivy") // will be uppercased automatically
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

func NewRootCommand(version string, globalFlags *flag.GlobalFlags) *cobra.Command {
	var versionFormat string
	cmd := &cobra.Command{
		Use:   "trivy [global flags] command [flags] target",
		Short: "Unified security scanner",
		Long:  "Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues and hard-coded secrets",
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		Args: cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cmd.SetOut(outputWriter)

			// Set the Trivy version here so that we can override version printer.
			cmd.Version = version

			// viper.BindPFlags cannot be called in init().
			// cf. https://github.com/spf13/cobra/issues/875
			//     https://github.com/spf13/viper/issues/233
			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				return err
			}
			if err := viper.BindPFlags(cmd.PersistentFlags()); err != nil {
				return err
			}

			// Initialize logger
			globalOptions := globalFlags.ToOptions()

			return log.InitLogger(globalOptions.Debug, globalOptions.Quiet)
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
	cmd.Flags().StringVarP(&versionFormat, flag.FormatFlag, "f", "", "version format (json)")

	globalFlags.AddFlags(cmd)

	return cmd
}

func NewImageCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	imageFlags := &flag.Flags{
		CacheFlags:   flag.NewCacheFlags(),
		DBFlags:      flag.NewDBFlags(),
		ImageFlags:   flag.NewImageFlags(), // container image specific
		MisconfFlags: flag.NewMisconfFlags(),
		RemoteFlags:  flag.NewClientFlags(), // for client/server mode
		ReportFlags:  flag.NewReportFlags(),
		ScanFlags:    flag.NewScanFlags(),
		SecretFlags:  flag.NewSecretFlags(),
	}

	cmd := &cobra.Command{
		Use:     "image [flags] IMAGE_NAME",
		Aliases: []string{"i"},
		Short:   "scan a container image",

		// 'Args' cannot be used since it is called before PersistentPreRunE and viper is not configured yet.
		// root.PersistentPreRunE -> configure viper
		// cmd.PreRunE            -> validate args
		// cmd.RunE               -> run the command
		PreRunE: validateArgs,
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

	return cmd
}

func NewFilesystemCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	fsFlags := &flag.Flags{
		CacheFlags:   flag.NewCacheFlags(),
		DBFlags:      flag.NewDBFlags(),
		MisconfFlags: flag.NewMisconfFlags(),
		RemoteFlags:  flag.NewClientFlags(), // for client/server mode
		ReportFlags:  flag.NewReportFlags(),
		ScanFlags:    flag.NewScanFlags(),
		SecretFlags:  flag.NewSecretFlags(),
	}

	cmd := &cobra.Command{
		Use:     "filesystem [flags] PATH",
		Aliases: []string{"fs"},
		Short:   "scan local filesystem",
		PreRunE: validateArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := fsFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetFilesystem)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	fsFlags.AddFlags(cmd)

	return cmd
}

func NewRootfsCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	rootfsFlags := &flag.Flags{
		CacheFlags:   flag.NewCacheFlags(),
		DBFlags:      flag.NewDBFlags(),
		MisconfFlags: flag.NewMisconfFlags(),
		ReportFlags:  flag.NewReportFlags(),
		ScanFlags:    flag.NewScanFlags(),
		SecretFlags:  flag.NewSecretFlags(),
	}

	cmd := &cobra.Command{
		Use:     "rootfs [flags] ROOTDIR",
		Short:   "scan rootfs",
		PreRunE: validateArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := rootfsFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetRootfs)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	rootfsFlags.AddFlags(cmd)

	return cmd
}

func NewRepositoryCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	repoFlags := &flag.Flags{
		CacheFlags:   flag.NewCacheFlags(),
		DBFlags:      flag.NewDBFlags(),
		MisconfFlags: flag.NewMisconfFlags(),
		RemoteFlags:  flag.NewClientFlags(), // for client/server mode
		ReportFlags:  flag.NewReportFlags(),
		ScanFlags:    flag.NewScanFlags(),
		SecretFlags:  flag.NewSecretFlags(),
	}

	cmd := &cobra.Command{
		Use:     "repository [flags] REPO_URL",
		Aliases: []string{"repo"},
		Short:   "scan remote repository",
		PreRunE: validateArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := repoFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetRepository)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	repoFlags.AddFlags(cmd)

	return cmd
}

// NewClientCommand returns the 'client' subcommand that is deprecated
func NewClientCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	remoteFlags := flag.NewClientFlags()
	remoteFlags.ServerAddr = nil // disable '--server' to use '--remote' instead.

	clientFlags := &flag.Flags{
		CacheFlags:   flag.NewCacheFlags(),
		DBFlags:      flag.NewDBFlags(),
		MisconfFlags: flag.NewMisconfFlags(),
		RemoteFlags:  remoteFlags,
		ReportFlags:  flag.NewReportFlags(),
		ScanFlags:    flag.NewScanFlags(),
		SecretFlags:  flag.NewSecretFlags(),
	}

	cmd := &cobra.Command{
		Use:     "client [flags] IMAGE_NAME",
		Aliases: []string{"c"},
		Hidden:  true, // 'client' command is deprecated
		PreRunE: validateArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Logger.Warn("'client' subcommand is deprecated now. See https://github.com/aquasecurity/trivy/discussions/2119")

			options, err := clientFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetContainerImage)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	clientFlags.AddFlags(cmd)

	// deprecated flags
	remoteFlags.ServerAddr = lo.ToPtr("")
	cmd.Flags().StringVar(remoteFlags.ServerAddr, "remote", "http://localhost:4954", "server address")
	viper.BindPFlag("remote", cmd.Flags().Lookup("remote")) // nolint: gosec

	return cmd
}

func NewServerCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	serverFlags := &flag.Flags{
		CacheFlags:  flag.NewCacheFlags(),
		DBFlags:     flag.NewDBFlags(),
		RemoteFlags: flag.NewServerDefaultFlags(),
		ReportFlags: flag.NewReportFlags(),
	}

	cmd := &cobra.Command{
		Use:     "server [flags]",
		Aliases: []string{"s"},
		Short:   "server mode",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := serverFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return server.Run(cmd.Context(), options)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	serverFlags.AddFlags(cmd)

	return cmd
}

func NewConfigCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	scanFlags := &flag.ScanFlags{
		// Enable only '--skip-dirs' and '--skip-files' and disable other flags
		SkipDirs:  lo.ToPtr([]string{}),
		SkipFiles: lo.ToPtr([]string{}),
	}

	configFlags := &flag.Flags{
		CacheFlags:   flag.NewCacheFlags(),
		MisconfFlags: flag.NewMisconfFlags(),
		ReportFlags:  flag.NewReportFlags(),
		ScanFlags:    scanFlags,
	}

	cmd := &cobra.Command{
		Use:     "config [flags] DIR",
		Aliases: []string{"conf"},
		Short:   "scan config files for misconfigurations",
		PreRunE: validateArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := configFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			// Disable OS and language analyzers
			options.DisabledAnalyzers = append(analyzer.TypeOSes, analyzer.TypeLanguages...)

			// Scan only for misconfigurations
			options.SecurityChecks = []string{types.SecurityCheckConfig}

			return artifact.Run(cmd.Context(), options, artifact.TargetFilesystem)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	configFlags.AddFlags(cmd)

	return cmd
}

func NewPluginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "plugin subcommand",
		Aliases:       []string{"p"},
		Short:         "manage plugins",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:     "install [flags] URL | FILE_PATH",
			Aliases: []string{"i"},
			Short:   "install a plugin",
			Args:    cobra.ExactArgs(1),
			RunE:    plugin.Install,
		},
		&cobra.Command{
			Use:     "uninstall PLUGIN_NAME",
			Aliases: []string{"u"},
			Short:   "uninstall a plugin",
			Args:    cobra.ExactArgs(1),
			RunE:    plugin.Uninstall,
		},
		&cobra.Command{
			Use:     "list",
			Aliases: []string{"l"},
			Short:   "list installed plugin",
			Args:    cobra.NoArgs,
			RunE:    plugin.List,
		},
		&cobra.Command{
			Use:   "info PLUGIN_NAME",
			Short: "information about a plugin",
			Args:  cobra.ExactArgs(1),
			RunE:  plugin.Information,
		},
	)
	return cmd
}

func NewModuleCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "module subcommand",
		Aliases:       []string{"m"},
		Short:         "manage modules",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	// Add subcommands
	cmd.AddCommand(
		&cobra.Command{
			Use:     "install [flags] REPOSITORY",
			Aliases: []string{"i"},
			Short:   "install a module",
			Args:    cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 1 {
					return cmd.Help()
				}

				repo := args[0]
				opts := globalFlags.ToOptions()
				return module.Install(cmd.Context(), repo, opts.Quiet, opts.Insecure)
			},
		},
		&cobra.Command{
			Use:     "uninstall [flags] REPOSITORY",
			Aliases: []string{"u"},
			Short:   "uninstall a module",
			Args:    cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 1 {
					return cmd.Help()
				}

				repo := args[0]
				return module.Uninstall(cmd.Context(), repo)
			},
		},
	)
	return cmd
}

func NewKubernetesCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	scanFlags := flag.NewScanFlags()
	scanFlags.SecurityChecks = lo.ToPtr(fmt.Sprintf( // overwrite the default value
		"%s,%s,%s,%s",
		types.SecurityCheckVulnerability,
		types.SecurityCheckConfig,
		types.SecurityCheckSecret, types.SecurityCheckRbac),
	)

	k8sFlags := &flag.Flags{
		CacheFlags:      flag.NewCacheFlags(),
		DBFlags:         flag.NewDBFlags(),
		KubernetesFlags: flag.NewKubernetesDefaultFlags(), // kubernetes-specific flags
		MisconfFlags:    flag.NewMisconfFlags(),
		ReportFlags:     flag.NewReportFlags(),
		ScanFlags:       scanFlags,
		SecretFlags:     flag.NewSecretFlags(),
	}
	cmd := &cobra.Command{
		Use:     "kubernetes [flags] { cluster | all | specific resources like kubectl. eg: pods, pod/NAME }",
		Aliases: []string{"k8s"},
		Short:   "scan kubernetes cluster",
		Example: `- cluster scanning:
      $ trivy k8s --report summary cluster
  - namespace scanning:
      $ trivy k8s -n kube-system --report summary all
  - resources scanning:
      $ trivy k8s --report=summary deploy
      $ trivy k8s --namespace=kube-system --report=summary deploy,configmaps
  - resource scanning:
      $ trivy k8s deployment/orion
`,
		PreRunE: validateArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := k8sFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			return k8scommands.Run(cmd.Context(), args, opts)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	k8sFlags.AddFlags(cmd)

	return cmd
}

func NewSBOMCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	scanFlags := flag.NewScanFlags()
	scanFlags.SecurityChecks = nil // disable '--security-checks' as it always scans for vulnerabilities

	sbomFlags := &flag.Flags{
		CacheFlags:  flag.NewCacheFlags(),
		DBFlags:     flag.NewDBFlags(),
		RemoteFlags: flag.NewClientFlags(), // for client/server mode
		ReportFlags: flag.NewReportFlags(),
		ScanFlags:   flag.NewScanFlags(),
		SBOMFlags:   flag.NewDefaultSBOMFlags(),
	}

	cmd := &cobra.Command{
		Use:   "sbom [flags] SBOM_PATH",
		Short: "scan SBOM for vulnerabilities",
		Example: `- Scan CycloneDX and show the result in tables:
      $ trivy sbom /path/to/report.cdx

  - Scan CycloneDX and generate a CycloneDX report:
      $ trivy sbom --format cyclonedx /path/to/report.cdx
`,
		PreRunE: validateArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := sbomFlags.ToOptions(cmd.Version, args, globalFlags, outputWriter)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetSBOM)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	sbomFlags.AddFlags(cmd)

	return cmd
}

func NewVersionCommand(globalFlags *flag.GlobalFlags) *cobra.Command {
	var versionFormat string
	cmd := &cobra.Command{
		Use:   "version [flags]",
		Short: "print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options := globalFlags.ToOptions()
			showVersion(options.CacheDir, versionFormat, cmd.Version, outputWriter)

			return nil
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	// Add version format flag, only json is supported
	cmd.Flags().StringVarP(&versionFormat, flag.FormatFlag, "f", "", "version format (json)")

	return cmd
}

func showVersion(cacheDir, outputFormat, version string, outputWriter io.Writer) {
	var dbMeta *metadata.Metadata

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

	switch outputFormat {
	case "json":
		b, _ := json.Marshal(VersionInfo{ // nolint: errcheck
			Version:         version,
			VulnerabilityDB: dbMeta,
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
		fmt.Fprintf(outputWriter, output)
	}
}

func validateArgs(cmd *cobra.Command, args []string) error {
	// '--clear-cache', '--download-db-only' and '--reset' don't conduct the scan
	if viper.GetBool(flag.ClearCacheFlag) || viper.GetBool(flag.DownloadDBOnlyFlag) || viper.GetBool(flag.ResetFlag) {
		return nil
	}

	if len(args) == 0 && viper.GetString(flag.InputFlag) == "" {
		if err := cmd.Help(); err != nil {
			return err
		}

		if f := cmd.Flags().Lookup(flag.InputFlag); f != nil {
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
