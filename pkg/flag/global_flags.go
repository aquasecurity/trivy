package flag

import (
	"crypto/x509"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	ConfigFileFlag = Flag[string]{
		Name:       "config",
		ConfigName: "config",
		Shorthand:  "c",
		Default:    "trivy.yaml",
		Usage:      "config path",
		Persistent: true,
	}
	ShowVersionFlag = Flag[bool]{
		Name:       "version",
		ConfigName: "version",
		Shorthand:  "v",
		Usage:      "show version",
		Persistent: true,
	}
	QuietFlag = Flag[bool]{
		Name:          "quiet",
		ConfigName:    "quiet",
		Shorthand:     "q",
		Usage:         "suppress progress bar and log output",
		Persistent:    true,
		TelemetrySafe: true,
	}
	DebugFlag = Flag[bool]{
		Name:          "debug",
		ConfigName:    "debug",
		Shorthand:     "d",
		Usage:         "debug mode",
		Persistent:    true,
		TelemetrySafe: true,
	}
	InsecureFlag = Flag[bool]{
		Name:          "insecure",
		ConfigName:    "insecure",
		Usage:         "allow insecure server connections",
		Persistent:    true,
		TelemetrySafe: true,
	}
	CACertFlag = Flag[string]{
		Name:       "cacert",
		ConfigName: "cacert",
		Usage:      "Path to PEM-encoded CA certificate file",
		Persistent: true,
	}
	TimeoutFlag = Flag[time.Duration]{
		Name:          "timeout",
		ConfigName:    "timeout",
		Default:       time.Second * 300, // 5 mins
		Usage:         "timeout",
		Persistent:    true,
		TelemetrySafe: true,
	}
	CacheDirFlag = Flag[string]{
		Name:       "cache-dir",
		ConfigName: "cache.dir",
		Default:    cache.DefaultDir(),
		Usage:      "cache directory",
		Persistent: true,
	}
	GenerateDefaultConfigFlag = Flag[bool]{
		Name:       "generate-default-config",
		ConfigName: "generate-default-config",
		Usage:      "write the default config to trivy-default.yaml",
		Persistent: true,
	}
	TraceHTTPFlag = Flag[bool]{
		Name:          "trace-http",
		ConfigName:    "trace.http",
		Usage:         "[DANGEROUS] enable HTTP request/response trace logging (may expose sensitive data)",
		Persistent:    true,
		TelemetrySafe: true,
		Internal:      true, // Hidden from help output, intended for maintainer debugging only
	}
	NoColorFlag = Flag[bool]{
		Name:       "no-color",
		ConfigName: "no-color",
		Usage:      "Remove color from output",
		Persistent: true,
	}
)

// GlobalFlagGroup composes global flags
type GlobalFlagGroup struct {
	ConfigFile            *Flag[string]
	ShowVersion           *Flag[bool] // spf13/cobra can't override the logic of version printing like VersionPrinter in urfave/cli. -v needs to be defined ourselves.
	Quiet                 *Flag[bool]
	Debug                 *Flag[bool]
	Insecure              *Flag[bool]
	CACert                *Flag[string]
	Timeout               *Flag[time.Duration]
	CacheDir              *Flag[string]
	GenerateDefaultConfig *Flag[bool]
	TraceHTTP             *Flag[bool]
	NoColor               *Flag[bool]
}

// GlobalOptions defines flags and other configuration parameters for all the subcommands
type GlobalOptions struct {
	ConfigFile            string
	ShowVersion           bool
	Quiet                 bool
	Debug                 bool
	Insecure              bool
	CACerts               *x509.CertPool
	Timeout               time.Duration
	CacheDir              string
	GenerateDefaultConfig bool
	TraceHTTP             bool
	NoColor               bool
}

func NewGlobalFlagGroup() *GlobalFlagGroup {
	return &GlobalFlagGroup{
		ConfigFile:            ConfigFileFlag.Clone(),
		ShowVersion:           ShowVersionFlag.Clone(),
		Quiet:                 QuietFlag.Clone(),
		Debug:                 DebugFlag.Clone(),
		Insecure:              InsecureFlag.Clone(),
		CACert:                CACertFlag.Clone(),
		Timeout:               TimeoutFlag.Clone(),
		CacheDir:              CacheDirFlag.Clone(),
		GenerateDefaultConfig: GenerateDefaultConfigFlag.Clone(),
		TraceHTTP:             TraceHTTPFlag.Clone(),
		NoColor:               NoColorFlag.Clone(),
	}
}

func (f *GlobalFlagGroup) Name() string {
	return "Global"
}

func (f *GlobalFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.ConfigFile,
		f.ShowVersion,
		f.Quiet,
		f.Debug,
		f.Insecure,
		f.CACert,
		f.Timeout,
		f.CacheDir,
		f.GenerateDefaultConfig,
		f.TraceHTTP,
		f.NoColor,
	}
}

func (f *GlobalFlagGroup) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.Flags() {
		flag.Add(cmd)
	}
}

func (f *GlobalFlagGroup) Bind(cmd *cobra.Command) error {
	for _, flag := range f.Flags() {
		if err := flag.Bind(cmd); err != nil {
			return err
		}
	}
	return nil
}

func (f *GlobalFlagGroup) ToOptions(opts *Options) error {
	// Keep TRIVY_NON_SSL for backward compatibility
	insecure := f.Insecure.Value() || os.Getenv("TRIVY_NON_SSL") != ""
	caCerts, err := loadRootCAs(f.CACert.Value())
	if err != nil {
		return xerrors.Errorf("failed to load root CA certificates: %w", err)
	}

	log.Debug("Cache dir", log.String("dir", f.CacheDir.Value()))

	opts.GlobalOptions = GlobalOptions{
		ConfigFile:            f.ConfigFile.Value(),
		ShowVersion:           f.ShowVersion.Value(),
		Quiet:                 f.Quiet.Value(),
		Debug:                 f.Debug.Value(),
		Insecure:              insecure,
		CACerts:               caCerts,
		Timeout:               f.Timeout.Value(),
		CacheDir:              f.CacheDir.Value(),
		GenerateDefaultConfig: f.GenerateDefaultConfig.Value(),
		TraceHTTP:             f.TraceHTTP.Value(),
		NoColor:               f.NoColor.Value(),
	}
	return nil
}

// loadRootCAs builds a cert pool from the system pool and the provided PEM bundle.
// Returns nil if caCertPath is empty or on failure.
func loadRootCAs(caCertPath string) (*x509.CertPool, error) {
	if caCertPath == "" {
		return nil, nil
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	pem, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, xerrors.Errorf("failed to read root CA certificate: %w", err)
	}
	if ok := rootCAs.AppendCertsFromPEM(pem); !ok {
		return nil, xerrors.Errorf("failed to append CA bundle")
	}
	return rootCAs, nil
}
