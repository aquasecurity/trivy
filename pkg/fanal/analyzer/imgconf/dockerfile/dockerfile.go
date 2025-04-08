package dockerfile

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/mapfs"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/version/doc"
)

var disabledChecks = []misconf.DisabledCheck{
	{
		ID: "DS007", Scanner: string(analyzer.TypeHistoryDockerfile),
		Reason: "See " + doc.URL("docs/target/container_image", "disabled-checks"),
	},
	{
		ID: "DS016", Scanner: string(analyzer.TypeHistoryDockerfile),
		Reason: "See " + doc.URL("docs/target/container_image", "disabled-checks"),
	},
}

const analyzerVersion = 1

func init() {
	analyzer.RegisterConfigAnalyzer(analyzer.TypeHistoryDockerfile, newHistoryAnalyzer)
}

type historyAnalyzer struct {
	scanner *misconf.Scanner
}

func newHistoryAnalyzer(opts analyzer.ConfigAnalyzerOptions) (analyzer.ConfigAnalyzer, error) {
	opts.MisconfScannerOption.DisabledChecks = append(opts.MisconfScannerOption.DisabledChecks, disabledChecks...)
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
		"Dockerfile", imageConfigToDockerfile(input.Config), 0600); err != nil {
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

	return &analyzer.ConfigAnalysisResult{
		Misconfiguration: &misconfs[0],
	}, nil
}

func imageConfigToDockerfile(cfg *v1.ConfigFile) []byte {
	dockerfile := new(bytes.Buffer)
	var userFound bool
	baseLayerIndex := image.GuessBaseImageIndex(cfg.History)
	for i := baseLayerIndex + 1; i < len(cfg.History); i++ {
		h := cfg.History[i]
		var createdBy string
		switch {
		case strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)"):
			// Instruction other than RUN
			createdBy = strings.TrimPrefix(h.CreatedBy, "/bin/sh -c #(nop)")
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
			userFound = true
		case strings.HasPrefix(h.CreatedBy, "HEALTHCHECK"):
			// HEALTHCHECK instruction
			createdBy = buildHealthcheckInstruction(cfg.Config.Healthcheck)
		default:
			for _, prefix := range []string{"ARG", "ENV", "ENTRYPOINT"} {
				if strings.HasPrefix(h.CreatedBy, prefix) {
					createdBy = h.CreatedBy
					break
				}
			}
		}
		dockerfile.WriteString(strings.TrimSpace(createdBy) + "\n")
	}

	if !userFound && cfg.Config.User != "" {
		user := fmt.Sprintf("USER %s", cfg.Config.User)
		dockerfile.WriteString(user)
	}

	return dockerfile.Bytes()
}

func buildRunInstruction(s string) string {
	pos := strings.Index(s, "/bin/sh -c")
	if pos == -1 {
		return s
	}
	return "RUN" + s[pos+len("/bin/sh -c"):]
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
		startPeriod = fmt.Sprintf("--startPeriod=%s ", health.StartPeriod)
	}
	if health.Retries != 0 {
		retries = fmt.Sprintf("--retries=%d ", health.Retries)
	}
	command = strings.Join(health.Test, " ")
	command = strings.ReplaceAll(command, "CMD-SHELL", "CMD")
	return fmt.Sprintf("HEALTHCHECK %s%s%s%s%s", interval, timeout, startPeriod, retries, command)
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
