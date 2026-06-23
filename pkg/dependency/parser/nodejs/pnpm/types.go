package pnpm

// PackageKey represents a key in the "packages" section of pnpm lock file.
// It consists of the package name and version without peer dependency information.
// This is different from the snapshot key which includes peer dependencies.
// Examples:
//   - "lodash@4.17.21"
//   - "@babel/core@7.21.0"
//   - "jest-config@30.0.3"
type PackageKey string

// SnapshotKey uniquely identifies a package instance in the "snapshots" section.
// In pnpm v9+, this includes peer dependency information to distinguish between
// different installations of the same package with different peer dependencies.
// Examples:
//   - "lodash@4.17.21"                                                    // no peers
//   - "jest-config@30.0.3(@types/node@24.0.7)(babel-plugin-macros@3.1.0)" // with peers
//   - "jest-pnp-resolver@1.2.3(jest-resolve@27.5.1)"                      // with peer
type SnapshotKey string

type PackageResolution struct {
	Tarball string `yaml:"tarball,omitempty"`
}

type PackageInfo struct {
	Resolution      PackageResolution `yaml:"resolution"`
	Dependencies    map[string]string `yaml:"dependencies,omitempty"`
	DevDependencies map[string]string `yaml:"devDependencies,omitempty"`
	IsDev           bool              `yaml:"dev,omitempty"`
	Name            string            `yaml:"name,omitempty"`
	Version         string            `yaml:"version,omitempty"`
}

type LockFile struct {
	LockfileVersion any                        `yaml:"lockfileVersion"`
	Dependencies    map[string]any             `yaml:"dependencies,omitempty"`
	DevDependencies map[string]any             `yaml:"devDependencies,omitempty"`
	Packages        map[PackageKey]PackageInfo `yaml:"packages,omitempty"`

	// V9: New fields introduced in pnpm v9 lock file format
	Importers map[string]Importer      `yaml:"importers,omitempty"`
	Snapshots map[SnapshotKey]Snapshot `yaml:"snapshots,omitempty"`
}

type Importer struct {
	Dependencies               map[string]ImporterDepVersion `yaml:"dependencies,omitempty"`
	DevDependencies            map[string]ImporterDepVersion `yaml:"devDependencies,omitempty"`
	ConfigDependencies         map[string]any                `yaml:"configDependencies,omitempty"`
	PackageManagerDependencies map[string]any                `yaml:"packageManagerDependencies,omitempty"`
}

// isEnvLockfile reports whether this YAML document is the pnpm env lockfile
// (config and package manager dependencies), which pnpm 11 stores as a
// separate document in pnpm-lock.yaml. It holds the package manager
// environment, not the project dependencies, so it must be skipped.
func (l LockFile) isEnvLockfile() bool {
	for _, importer := range l.Importers {
		if importer.ConfigDependencies != nil || importer.PackageManagerDependencies != nil {
			return true
		}
	}
	return false
}

type ImporterDepVersion struct {
	Version string `yaml:"version,omitempty"`
}

type Snapshot struct {
	Dependencies         map[string]string `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies,omitempty"`
}
