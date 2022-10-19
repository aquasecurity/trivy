/*
 * Copyright (c) 2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

package wrlinux

import (
	"time"

	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/wrlinux"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
	"fmt"
	"strings"
	"strconv"
)

var (
	eolDates = map[string]time.Time{
		"10.19": time.Date(2024, 11, 30, 23, 59, 59, 0, time.UTC),
		"10.21": time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}
)

type options struct {
	clock clock.Clock
}

type option func(*options)

func WithClock(clock clock.Clock) option {
	return func(opts *options) {
		opts.clock = clock
	}
}

// Scanner implements the WRLinux scanner
type Scanner struct {
	vs wrlinux.VulnSrc
	*options
}

// NewScanner is the factory method for Scanner
func NewScanner(opts ...option) *Scanner {
	o := &options{
		clock: clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}
	return &Scanner{
		vs:      wrlinux.NewVulnSrc(),
		options: o,
	}
}

// Detect scans and returns vulnerabilities using wrlinux scanner
func (s *Scanner) Detect(osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Wind River Linux vulnerabilities...")
	log.Logger.Debugf("Wind River Linux: os version: %s", osVer)
	log.Logger.Debugf("Wind River Linux: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Wind River Linux advisory: %w", err)
		}

		for _, adv := range advisories {
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatSrcVersion(pkg),
				FixedVersion:     adv.FixedVersion,
				Ref:              pkg.Ref,
				Layer:            pkg.Layer,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			}

			if adv.FixedVersion == "" {
				vulns = append(vulns, vuln)
				continue
			}
			if osVerLT(osVer, adv.FixedVersion) {
				vuln.FixedVersion = adv.FixedVersion
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks if the OS version reached end-of-support.
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	release := OsVerToRelease(osVer)
	if release == "LINCD" {
		return true
	}
	eol, ok := eolDates[release]
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}
	return s.clock.Now().Before(eol)
}


// returns true if s1, is strictly less that s2
// 		   false otherwise
func osVerLT(s1, s2 string) bool {
	s1_spl := strings.Split(s1, ".")
	s2_spl := strings.Split(s2, ".")
	for i, _ := range s1_spl {
		n1, err1 := strconv.Atoi(s1_spl[i])
		if err1 != nil {
			fmt.Printf("n1 error\n")
		}
		n2, err2 := strconv.Atoi(s2_spl[i])
		if err2 != nil {
			fmt.Printf("n2 error\n")
		}
		if n1 < n2 {
			return true
		}
	}
	return false
}

// gets the release from the osVersion
// "w.x.y.z" -> "w.x"
func OsVerToRelease(osVer string) string {
	s := strings.Split(osVer, ".")
	if s[len(s)-1] == "0" {
		return "LINCD"
	}
	return strings.Join(s[:2], ".")
}
