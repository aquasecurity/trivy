package flag

var (
	CleanAll = Flag[bool]{
		Name:       "all",
		Shorthand:  "a",
		ConfigName: "clean.all",
		Usage:      "remove all caches",
	}
	CleanScanCache = Flag[bool]{
		Name:       "scan-cache",
		ConfigName: "clean.scan-cache",
		Usage:      "remove scan cache (container and VM image analysis results)",
	}
	CleanVulnerabilityDB = Flag[bool]{
		Name:       "vuln-db",
		ConfigName: "clean.vuln-db",
		Usage:      "remove vulnerability database",
	}
	CleanJavaDB = Flag[bool]{
		Name:       "java-db",
		ConfigName: "clean.java-db",
		Usage:      "remove Java database",
	}
	CleanChecksBundle = Flag[bool]{
		Name:       "checks-bundle",
		ConfigName: "clean.checks-bundle",
		Usage:      "remove checks bundle",
	}
)

type CleanFlagGroup struct {
	CleanAll             *Flag[bool]
	CleanVulnerabilityDB *Flag[bool]
	CleanJavaDB          *Flag[bool]
	CleanChecksBundle    *Flag[bool]
	CleanScanCache       *Flag[bool]
}

type CleanOptions struct {
	CleanAll             bool
	CleanVulnerabilityDB bool
	CleanJavaDB          bool
	CleanChecksBundle    bool
	CleanScanCache       bool
}

func NewCleanFlagGroup() *CleanFlagGroup {
	return &CleanFlagGroup{
		CleanAll:             CleanAll.Clone(),
		CleanVulnerabilityDB: CleanVulnerabilityDB.Clone(),
		CleanJavaDB:          CleanJavaDB.Clone(),
		CleanChecksBundle:    CleanChecksBundle.Clone(),
		CleanScanCache:       CleanScanCache.Clone(),
	}
}

func (fg *CleanFlagGroup) Name() string {
	return "Clean"
}

func (fg *CleanFlagGroup) Flags() []Flagger {
	return []Flagger{
		fg.CleanAll,
		fg.CleanVulnerabilityDB,
		fg.CleanJavaDB,
		fg.CleanChecksBundle,
		fg.CleanScanCache,
	}
}

func (fg *CleanFlagGroup) ToOptions() (CleanOptions, error) {
	if err := parseFlags(fg); err != nil {
		return CleanOptions{}, err
	}

	return CleanOptions{
		CleanAll:             fg.CleanAll.Value(),
		CleanVulnerabilityDB: fg.CleanVulnerabilityDB.Value(),
		CleanJavaDB:          fg.CleanJavaDB.Value(),
		CleanChecksBundle:    fg.CleanChecksBundle.Value(),
		CleanScanCache:       fg.CleanScanCache.Value(),
	}, nil
}
