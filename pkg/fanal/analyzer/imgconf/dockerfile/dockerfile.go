package dockerfile

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/mapfs"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/version/doc"
)

var (
	disabledChecks = set.New("DS-0007", "DS-0016")
	reason         = "See " + doc.URL("guide/target/container_image", "disabled-checks")
)

const analyzerVersion = 1

func init() {
	analyzer.RegisterConfigAnalyzer(analyzer.TypeHistoryDockerfile, newHistoryAnalyzer)
}

type historyAnalyzer struct {
	scanner *misconf.Scanner
}

func newHistoryAnalyzer(opts analyzer.ConfigAnalyzerOptions) (analyzer.ConfigAnalyzer, error) {
	s, err := misconf.NewScanner(detection.FileTypeDockerfile, opts.MisconfScannerOption)
	if err != nil {
		return nil, xerrors.Errorf("misconfiguration scanner error: %w", err)
	}
	return &historyAnalyzer{
		scanner: s,
	}, nil
}

func (a *historyAnalyzer) Analyze(ctx context.Context, input analyzer.ConfigAnalysisInput) (*analyzer.
	ConfigAnalysisResult, error) {
	if input.Config == nil {
		return nil, nil
	}

	fsys := mapfs.New()
	if err := fsys.WriteVirtualFile(
		"Dockerfile", imageConfigToDockerfile(input.Config), 0o600); err != nil {
		return nil, xerrors.Errorf("mapfs write error: %w", err)
	}

	misconfs, err := a.scanner.Scan(ctx, fsys)
	if err != nil {
		return nil, xerrors.Errorf("history scan error: %w", err)
	}
	// The result should be a single element as it passes one Dockerfile.
	if len(misconfs) != 1 {
		return nil, nil
	}

	misconfig := misconfs[0]
	misconfig.Failures = filterDisabledChecks(misconfig.Failures)
	return &analyzer.ConfigAnalysisResult{
		Misconfiguration: &misconfig,
	}, nil
}

func imageConfigToDockerfile(cfg *v1.ConfigFile) []byte {
	dockerfile := new(bytes.Buffer)
	baseLayerIndex := image.GuessBaseImageIndex(cfg.History)
	for i := baseLayerIndex + 1; i < len(cfg.History); i++ {
		h := cfg.History[i]
		var createdBy string
		switch {
		case strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)"):
			// Instruction other than RUN
			createdBy = strings.TrimPrefix(h.CreatedBy, "/bin/sh -c #(nop)")
			if strings.HasPrefix(createdBy, " COPY") || strings.HasPrefix(createdBy, " ADD") {
				createdBy = normalizeCopyCreatedBy(createdBy)
			}
		case strings.HasPrefix(h.CreatedBy, "/bin/sh -c"):
			// RUN instruction
			createdBy = buildRunInstruction(createdBy)
		case strings.HasSuffix(h.CreatedBy, "# buildkit"):
			// buildkit instructions
			// COPY ./foo /foo # buildkit
			// ADD ./foo.txt /foo.txt # buildkit
			// RUN /bin/sh -c ls -hl /foo # buildkit
			createdBy = strings.TrimSuffix(h.CreatedBy, "# buildkit")
			createdBy = buildRunInstruction(createdBy)
		case strings.HasPrefix(h.CreatedBy, "USER"):
			// USER instruction
			createdBy = h.CreatedBy
		case strings.HasPrefix(h.CreatedBy, "HEALTHCHECK"):
			// HEALTHCHECK instruction
			createdBy = buildHealthcheckInstruction(cfg.Config.Healthcheck)
		case strings.HasPrefix(h.CreatedBy, "ENV"):
			createdBy = restoreEnvLine(h.CreatedBy)
		default:
			for _, prefix := range []string{"ARG", "ENTRYPOINT"} {
				if strings.HasPrefix(h.CreatedBy, prefix) {
					createdBy = h.CreatedBy
					break
				}
			}
		}

		createdBy = stripBuildMetadata(createdBy)
		dockerfile.WriteString(strings.TrimSpace(createdBy) + "\n")
	}

	// The user can be changed from the config file or with the `--user` flag (for docker CLI), so we need to add this user to avoid incorrect user detection
	if cfg.Config.User != "" {
		user := fmt.Sprintf("USER %s", cfg.Config.User)
		dockerfile.WriteString(user)
	}

	return dockerfile.Bytes()
}

var metadataRe = regexp.MustCompile(`\|[a-zA-Z0-9_-]+=[^ \t]+`)

// stripBuildMetadata removes build metadata suffixes appended by container build backends
// (e.g., Buildah, Buildkit). Each suffix has the form "|key=value".
// Example: "/bin/sh -c #(nop) HEALTHCHECK NONE|unsetLabel=true|inheritLabels=false|force-mtime=10"
// c.f. Buildah source for metadata construction:
// https://github.com/containers/buildah/blob/fb473e4d538f693f8b3ee3f8f2ed93a2abed5064/imagebuildah/stage_executor.go#L2616
func stripBuildMetadata(line string) string {
	return metadataRe.ReplaceAllString(line, "")
}

func buildRunInstruction(s string) string {
	_, after, ok := strings.Cut(s, "/bin/sh -c")
	if !ok {
		return s
	}
	return "RUN" + after
}

func buildHealthcheckInstruction(health *v1.HealthConfig) string {
	var interval, timeout, startPeriod, retries, command string
	if health.Interval != 0 {
		interval = fmt.Sprintf("--interval=%s ", health.Interval)
	}
	if health.Timeout != 0 {
		timeout = fmt.Sprintf("--timeout=%s ", health.Timeout)
	}
	if health.StartPeriod != 0 {
		startPeriod = fmt.Sprintf("--start-period=%s ", health.StartPeriod)
	}
	if health.Retries != 0 {
		retries = fmt.Sprintf("--retries=%d ", health.Retries)
	}
	command = strings.Join(health.Test, " ")
	command = strings.ReplaceAll(command, "CMD-SHELL", "CMD")
	return fmt.Sprintf("HEALTHCHECK %s%s%s%s%s", interval, timeout, startPeriod, retries, command)
}

var copyInRe = regexp.MustCompile(`\b((?:file|dir):\S+) in `)

func normalizeCopyCreatedBy(input string) string {
	return copyInRe.ReplaceAllString(input, `$1 `)
}

// restoreEnvLine normalizes a Dockerfile ENV instruction from image history.
//
// Legacy Dockerfiles may use ENV in the form: "ENV key val1 val2".
// Docker stores this in image history as: "ENV key=val1 val2".
// This can cause parsing errors, because extra tokens are treated as separate keys.
// restoreEnvLine converts such lines into a valid `ENV <key>="<value>"` format
// and wraps the value in quotes to preserve internal spaces and tabs.
// e.g. `ENV tags=latest v0.0.0` -> `ENV key="latest v0.0.0"`
func restoreEnvLine(createdBy string) string {
	k, v, ok := strings.Cut(createdBy, "=")
	if !ok {
		return createdBy
	}
	return fmt.Sprintf("%s=%q", k, v)
}

func (a *historyAnalyzer) Required(_ types.OS) bool {
	return true
}

func (a *historyAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHistoryDockerfile
}

func (a *historyAnalyzer) Version() int {
	return analyzerVersion
}

func filterDisabledChecks(results types.MisconfResults) types.MisconfResults {
	var filtered types.MisconfResults
	for _, r := range results {
		if disabledChecks.Contains(r.ID) {
			log.WithPrefix("image history analyzer").Info("Skip disabled check",
				log.String("ID", r.ID), log.String("reason", reason))
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}
