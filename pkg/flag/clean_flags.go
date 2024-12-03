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
	CleanVEXRepo = Flag[bool]{
		Name:       "vex-repo",
		ConfigName: "clean.vex-repo",
		Usage:      "remove VEX repositories",
	}
)

type CleanFlagGroup struct {
	CleanAll             *Flag[bool]
	CleanScanCache       *Flag[bool]
	CleanVulnerabilityDB *Flag[bool]
	CleanJavaDB          *Flag[bool]
	CleanChecksBundle    *Flag[bool]
	CleanVEXRepositories *Flag[bool]
}

type CleanOptions struct {
	CleanAll             bool
	CleanScanCache       bool
	CleanVulnerabilityDB bool
	CleanJavaDB          bool
	CleanChecksBundle    bool
	CleanVEXRepositories bool
}

func NewCleanFlagGroup() *CleanFlagGroup {
	return &CleanFlagGroup{
		CleanAll:             CleanAll.Clone(),
		CleanScanCache:       CleanScanCache.Clone(),
		CleanVulnerabilityDB: CleanVulnerabilityDB.Clone(),
		CleanJavaDB:          CleanJavaDB.Clone(),
		CleanChecksBundle:    CleanChecksBundle.Clone(),
		CleanVEXRepositories: CleanVEXRepo.Clone(),
	}
}

func (fg *CleanFlagGroup) Name() string {
	return "Clean"
}

func (fg *CleanFlagGroup) Flags() []Flagger {
	return []Flagger{
		fg.CleanAll,
		fg.CleanScanCache,
		fg.CleanVulnerabilityDB,
		fg.CleanJavaDB,
		fg.CleanChecksBundle,
		fg.CleanVEXRepositories,
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
		CleanVEXRepositories: fg.CleanVEXRepositories.Value(),
	}, nil
}
