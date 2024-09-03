//go:build mage_vex

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/vuln/scan"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	repoURL    = "https://github.com/aquasecurity/trivy"
	minVersion = "0.40.0"
)

var (
	minVer, _ = version.Parse(minVersion)

	// Product ID for Trivy
	productID = &packageurl.PackageURL{
		Type: packageurl.TypeGolang,
		// According to https://github.com/package-url/purl-spec/issues/63,
		// It's probably better to leave namespace empty and put a module name into `name`.
		Namespace: "",
		Name:      "github.com/aquasecurity/trivy",
	}
)

// VulnerabilityFinding is for parsing govulncheck JSON output
type VulnerabilityFinding struct {
	Finding Finding `json:"finding"`
}

type Finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []Trace `json:"trace"`
}

type Trace struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Package string `json:"package"`
}

// UniqueKey is used to identify unique vulnerability-subcomponent pairs
type UniqueKey struct {
	VulnerabilityID vex.VulnerabilityID
	SubcomponentID  string
}

func main() {
	if err := run(); err != nil {
		log.Fatal("Fatal error", log.Err(err))
	}
}

// run is the main entry point for the VEX generator
func run() error {
	log.InitLogger(false, false)

	// Parse command-line flags
	cloneDir := flag.String("dir", "trivy", "Directory to clone the repository")
	output := flag.String("output", ".vex/trivy.openvex.json", "Output file")
	flag.Parse()

	ctx := context.Background()

	// Clone or pull the Trivy repository
	if _, err := cloneOrPullRepo(ctx, *cloneDir); err != nil {
		return err
	}

	defer func() {
		// Ensure we are on the main branch after processing
		_, _ = checkoutMain(ctx, *cloneDir)
	}()

	// Save the current working directory
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	// Change to the target directory as govulncheck doesn't support Dir
	// cf. https://github.com/golang/go/blob/6d89b38ed86e0bfa0ddaba08dc4071e6bb300eea/src/os/exec/exec.go#L171-L174
	if err = os.Chdir(*cloneDir); err != nil {
		return fmt.Errorf("failed to change to directory %s: %w", *cloneDir, err)
	}

	// Get the latest tags from the repository
	tags, err := getLatestTags(ctx)
	if err != nil {
		return err
	}
	log.Info("Latest tags", log.Any("tags", tags))

	// Maps to store "not_affected" statements across Trivy versions
	notAffectedVulns := make(map[UniqueKey][]vex.Statement)

	// Indicate one or more Trivy versions are affected by the vulnerability.
	// This means that the version cannot be omitted later.
	affectedVulns := make(map[UniqueKey]struct{})

	// Process each tag
	for _, tag := range tags {
		notAffected, affected, err := processTag(ctx, tag)
		if err != nil {
			return err
		}
		log.Info("Processed tag", log.String("tag", tag),
			log.Int("not_affected", len(notAffected)), log.Int("affected", len(affected)))
		lo.Assign(affectedVulns, affected)
		for k, v := range notAffected {
			notAffectedVulns[k] = append(notAffectedVulns[k], v)
		}
	}

	// Change back to the original directory
	if err = os.Chdir(wd); err != nil {
		return fmt.Errorf("failed to change back to original directory: %w", err)
	}

	// Generate the final VEX document
	if err = updateVEX(*output, combineDocs(notAffectedVulns, affectedVulns)); err != nil {
		return err
	}

	return nil
}

// cloneOrPullRepo clones the Trivy repository or pulls updates if it already exists
func cloneOrPullRepo(ctx context.Context, dir string) ([]byte, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return runCommandWithTimeout(ctx, 20*time.Minute, "git", "clone", repoURL, dir)
	}

	if _, err := checkoutMain(ctx, dir); err != nil {
		return nil, fmt.Errorf("failed to checkout main: %w", err)
	}
	return runCommandWithTimeout(ctx, 2*time.Minute, "git", "-C", dir, "pull", "--tags")
}

// checkoutMain checks out the main branch of the repository
func checkoutMain(ctx context.Context, dir string) ([]byte, error) {
	return runCommandWithTimeout(ctx, 1*time.Minute, "git", "-C", dir, "checkout", "main")
}

// getLatestTags retrieves and sorts the latest tags from the repository
func getLatestTags(ctx context.Context) ([]string, error) {
	output, err := runCommandWithTimeout(ctx, 1*time.Minute, "git", "tag")
	if err != nil {
		return nil, fmt.Errorf("failed to get tags: %w", err)
	}

	tags := strings.Split(strings.TrimSpace(string(output)), "\n")
	versions := make([]string, 0, len(tags))

	for _, tag := range tags {
		v, err := version.Parse(tag)
		if err != nil {
			continue
		}
		if v.GreaterThanOrEqual(minVer) {
			versions = append(versions, tag)
		}
	}

	return versions, nil
}

// processTag processes a single tag, running govulncheck and generating VEX statements
func processTag(ctx context.Context, tag string) (map[UniqueKey]vex.Statement, map[UniqueKey]struct{}, error) {
	log.Info("Processing tag...", log.String("tag", tag))
	if _, err := runCommandWithTimeout(ctx, 1*time.Minute, "git", "checkout", tag); err != nil {
		return nil, nil, fmt.Errorf("failed to checkout tag %s: %w", tag, err)
	}

	// Run govulncheck and generate VEX document
	vexDoc, err := generateVEX(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run govulncheck: %w", err)
	}

	// Run govulncheck and generate JSON result
	// Need to generate JSON as well as OpenVEX for the following reasons:
	//   - Subcomponent
	//      - OpenVEX from govulncheck doesn't fill in subcomponents.
	//   - Status
	//      - govulncheck uses "not_affected" for all vulnerabilities. Need to determine "fixed" vulnerabilities.
	//        cf. https://github.com/golang/go/issues/68338
	findings, err := generateJSON(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run govulncheck: %w", err)
	}

	product := *productID // Clone Trivy PURL
	product.Version = tag
	notAffected := make(map[UniqueKey]vex.Statement)
	affected := make(map[UniqueKey]struct{})

	// Update VEX document generated by govulncheck
	for _, stmt := range vexDoc.Statements {
		finding, ok := findings[stmt.Vulnerability.Name]
		if !ok {
			// Considered as "fixed" vulnerabilities
			// cf. https://github.com/golang/go/issues/68338
			continue
		} else if len(finding.Finding.Trace) == 0 {
			continue
		}

		namespace, name := path.Split(finding.Finding.Trace[0].Module)
		subcomponent := &packageurl.PackageURL{
			Type:      packageurl.TypeGolang,
			Namespace: namespace,
			Name:      name,
		}

		key := UniqueKey{
			VulnerabilityID: stmt.Vulnerability.Name,
			SubcomponentID:  subcomponent.String(),
		}

		if stmt.Status == vex.StatusAffected {
			affected[key] = struct{}{}
			continue
		} else if stmt.Status != vex.StatusNotAffected {
			continue
		}

		// Update the statement with product and subcomponent information
		stmt.Products = []vex.Product{
			{
				// Fill in components manually
				// cf. https://github.com/golang/go/issues/68152
				Component: vex.Component{
					ID: product.String(),
					Identifiers: map[vex.IdentifierType]string{
						vex.PURL: product.String(),
					},
				},
				Subcomponents: []vex.Subcomponent{
					{
						Component: vex.Component{
							ID: key.SubcomponentID,
							Identifiers: map[vex.IdentifierType]string{
								vex.PURL: key.SubcomponentID,
							},
						},
					},
				},
			},
		}
		notAffected[key] = stmt
	}

	return notAffected, affected, nil
}

// generateVEX runs govulncheck with OpenVEX format and parses the output
func generateVEX(ctx context.Context) (*vex.VEX, error) {
	buf, err := runGovulncheck(ctx, "openvex")
	if err != nil {
		return nil, fmt.Errorf("failed to run govulncheck: %w", err)
	}

	vexDoc, err := vex.Parse(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to parse govulncheck output: %w", err)
	}
	return vexDoc, nil
}

// generateJSON runs govulncheck with JSON format and parses the output
func generateJSON(ctx context.Context) (map[vex.VulnerabilityID]VulnerabilityFinding, error) {
	buf, err := runGovulncheck(ctx, "json")
	if err != nil {
		return nil, fmt.Errorf("failed to run govulncheck: %w", err)
	}

	decoder := json.NewDecoder(buf)
	findings := make(map[vex.VulnerabilityID]VulnerabilityFinding)
	for {
		var finding VulnerabilityFinding
		if err := decoder.Decode(&finding); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to decode govulncheck output: %w", err)
		}
		findings[vex.VulnerabilityID(finding.Finding.OSV)] = finding
	}
	return findings, nil
}

// runGovulncheck executes the govulncheck command with the specified format
func runGovulncheck(ctx context.Context, format string) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	cmd := scan.Command(ctx, "-format", format, "./...")
	cmd.Stdout = &buf

	log.Info("Running govulncheck", log.String("format", format))
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start govulncheck: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("failed to run govulncheck: %w", err)
	}
	return &buf, nil
}

// combineDocs merges the VEX statements from all processed tags
func combineDocs(notAffected map[UniqueKey][]vex.Statement, affected map[UniqueKey]struct{}) []vex.Statement {
	log.Info("Combining VEX documents")
	statements := make(map[UniqueKey]vex.Statement)
	for key, stmts := range notAffected {
		for _, stmt := range stmts {
			if _, ok := affected[key]; !ok {
				// All versions are "not_affected" or "fixed" by the vulnerability, omitting a version in PURL
				// => pkg:golang/github.com/aquasecurity/trivy
				stmt.Products[0].ID = productID.String()
				stmt.Products[0].Identifiers[vex.PURL] = productID.String()
				statements[key] = stmt
				break
			}

			// At least one version is "affected" by the vulnerability, so we need to include the version in PURL.
			// => pkg:golang/github.com/aquasecurity/trivy@0.52.0
			if s, ok := statements[key]; ok {
				s.Products = append(s.Products, stmt.Products...)
				statements[key] = s
			} else {
				statements[key] = stmt
			}
		}
	}
	return lo.Values(statements)
}

// runCommandWithTimeout executes a command with a specified timeout
func runCommandWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	log.Info("Executing command", log.String("cmd", cmd.String()))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%w, output: %s", err, string(output))
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("command timed out after %v", timeout)
	}

	return output, nil
}

// updateVEX updates the final VEX document with the combined statements
func updateVEX(output string, statements []vex.Statement) error {
	doc, err := vex.Load(output)
	if errors.Is(err, os.ErrNotExist) {
		doc = &vex.VEX{}
	} else if err != nil {
		return err
	}

	vex.SortStatements(statements, time.Now())
	d := &vex.VEX{
		Metadata: vex.Metadata{
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "Aqua Security",
			Timestamp: lo.ToPtr(time.Now()),
			Version:   doc.Version + 1,
			Tooling:   "https://github.com/aquasecurity/trivy/tree/main/magefiles/vex.go",
		},
		Statements: statements,
	}
	h, err := hashVEX(d)
	if err != nil {
		return err
	}
	d.ID = "aquasecurity/trivy:" + h

	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	if err = e.Encode(d); err != nil {
		return err
	}
	return err
}

func hashVEX(d *vex.VEX) (string, error) {
	out, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(out)), nil
}
