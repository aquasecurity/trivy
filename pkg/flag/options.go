package flag

import (
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

type Flags struct {
	CacheFlags      *CacheFlags
	DBFlags         *DBFlags
	ImageFlags      *ImageFlags
	KubernetesFlags *KubernetesFlags
	MisconfFlags    *MisconfFlags
	RemoteFlags     *RemoteFlags
	ReportFlags     *ReportFlags
	SBOMFlags       *SBOMFlags
	ScanFlags       *ScanFlags
	SecretFlags     *SecretFlags
}

// Options holds all the runtime configuration
type Options struct {
	GlobalOptions
	CacheOptions
	DBOptions
	ImageOptions
	KubernetesOptions
	MisconfOptions
	RemoteOptions
	ReportOptions
	SBOMOptions
	ScanOptions
	SecretOptions

	// Trivy's version, not populated via CLI flags
	AppVersion string

	// We don't want to allow disabled analyzers to be passed by users, but it is necessary for internal use.
	DisabledAnalyzers []analyzer.Type
}

func (f *Flags) AddFlags(cmd *cobra.Command) {
	if f.CacheFlags != nil {
		f.CacheFlags.AddFlags(cmd)
	}
	if f.DBFlags != nil {
		f.DBFlags.AddFlags(cmd)
	}
	if f.ImageFlags != nil {
		f.ImageFlags.AddFlags(cmd)
	}
	if f.KubernetesFlags != nil {
		f.KubernetesFlags.AddFlags(cmd)
	}
	if f.MisconfFlags != nil {
		f.MisconfFlags.AddFlags(cmd)
	}
	if f.RemoteFlags != nil {
		f.RemoteFlags.AddFlags(cmd)
	}
	if f.ReportFlags != nil {
		f.ReportFlags.AddFlags(cmd)
	}
	if f.SBOMFlags != nil {
		f.SBOMFlags.AddFlags(cmd)
	}
	if f.ScanFlags != nil {
		f.ScanFlags.AddFlags(cmd)
	}
	if f.SecretFlags != nil {
		f.SecretFlags.AddFlags(cmd)
	}

	cmd.Flags().SetNormalizeFunc(flagNameNormalize)
}

func (f *Flags) ToOptions(appVersion string, args []string, globalFlags *GlobalFlags, output io.Writer) (Options, error) {
	var err error
	opts := Options{
		AppVersion:    appVersion,
		GlobalOptions: globalFlags.ToOptions(),
	}

	if f.CacheFlags != nil {
		opts.CacheOptions, err = f.CacheFlags.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("cache flag error: %w", err)
		}
	}

	if f.DBFlags != nil {
		opts.DBOptions, err = f.DBFlags.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("flag error: %w", err)
		}
	}

	if f.ImageFlags != nil {
		opts.ImageOptions = f.ImageFlags.ToOptions()
	}

	if f.KubernetesFlags != nil {
		opts.KubernetesOptions = f.KubernetesFlags.ToOptions()
	}

	if f.MisconfFlags != nil {
		opts.MisconfOptions, err = f.MisconfFlags.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("misconfiguration flag error: %w", err)
		}
	}

	if f.RemoteFlags != nil {
		opts.RemoteOptions = f.RemoteFlags.ToOptions()
	}

	if f.ReportFlags != nil {
		opts.ReportOptions, err = f.ReportFlags.ToOptions(output)
		if err != nil {
			return Options{}, xerrors.Errorf("report flag error: %w", err)
		}
	}

	if f.SBOMFlags != nil {
		opts.SBOMOptions, err = f.SBOMFlags.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("sbom flag error: %w", err)
		}
	}

	if f.ScanFlags != nil {
		opts.ScanOptions, err = f.ScanFlags.ToOptions(args)
		if err != nil {
			return Options{}, xerrors.Errorf("scanning flag error: %w", err)
		}
	}

	if f.SecretFlags != nil {
		opts.SecretOptions = f.SecretFlags.ToOptions()
	}

	return opts, nil
}

func flagNameNormalize(f *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "skip-update":
		name = SkipDBUpdateFlag
	case "policy":
		name = ConfigPolicyFlag
	case "data":
		name = ConfigDataFlag
	case "namespaces", "policy-namespaces":
		name = PolicyNamespaceFlag
	case "ctx":
		name = ClusterContextFlag
	}
	return pflag.NormalizedName(name)
}
