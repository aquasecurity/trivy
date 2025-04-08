package plugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const indexURL = "https://aquasecurity.github.io/trivy-plugin-index/v1/index.yaml"

type Index struct {
	Version int `yaml:"version"`
	Plugins []struct {
		Name       string `yaml:"name"`
		Version    string `yaml:"version"`
		Maintainer string `yaml:"maintainer"`
		Summary    string `yaml:"summary"`
		Repository string `yaml:"repository"`
		Output     bool   `yaml:"output"`
	} `yaml:"plugins"`
}

func (m *Manager) Update(ctx context.Context, opts Options) error {
	m.logger.InfoContext(ctx, "Updating the plugin index...", log.String("url", m.indexURL))
	if _, err := downloader.Download(ctx, m.indexURL, filepath.Dir(m.indexPath), "",
		downloader.Options{Insecure: opts.Insecure}); err != nil {
		return xerrors.Errorf("unable to download the plugin index: %w", err)
	}
	return nil
}

func (m *Manager) Search(ctx context.Context, keyword string) error {
	index, err := m.loadIndex()
	if errors.Is(err, os.ErrNotExist) {
		m.logger.ErrorContext(ctx, "The plugin index is not found. Please run 'trivy plugin update' to download the index.")
		return xerrors.Errorf("plugin index not found: %w", err)
	} else if err != nil {
		return xerrors.Errorf("unable to load the plugin index: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%-20s %-60s %-20s %s\n", "NAME", "DESCRIPTION", "MAINTAINER", "OUTPUT"))
	for _, p := range index.Plugins {
		if keyword == "" || strings.Contains(p.Name, keyword) || strings.Contains(p.Summary, keyword) {
			s := fmt.Sprintf("%-20s %-60s %-20s %s\n", truncateString(p.Name, 20),
				truncateString(p.Summary, 60), truncateString(p.Maintainer, 20),
				lo.Ternary(p.Output, "  ✓", ""))
			buf.WriteString(s)
		}
	}

	if _, err = fmt.Fprint(m.w, buf.String()); err != nil {
		return err
	}

	return nil
}

// tryIndex returns the repository URL if the plugin name is found in the index.
// Otherwise, it returns the input name.
func (m *Manager) tryIndex(ctx context.Context, name string, opts Options) string {
	// If the index file does not exist, download it first.
	if !fsutils.FileExists(m.indexPath) {
		if err := m.Update(ctx, opts); err != nil {
			m.logger.ErrorContext(ctx, "Failed to update the plugin index", log.Err(err))
			return name
		}
	}

	index, err := m.loadIndex()
	if errors.Is(err, os.ErrNotExist) {
		m.logger.WarnContext(ctx, "The plugin index is not found. Please run 'trivy plugin update' to download the index.")
		return name
	} else if err != nil {
		m.logger.ErrorContext(ctx, "Unable to load the plugin index", log.Err(err))
		return name
	}

	for _, p := range index.Plugins {
		if p.Name == name {
			return p.Repository
		}
	}
	return name
}

func (m *Manager) loadIndex() (*Index, error) {
	f, err := os.Open(m.indexPath)
	if err != nil {
		return nil, xerrors.Errorf("unable to open the index file: %w", err)
	}
	defer f.Close()

	var index Index
	if err = yaml.NewDecoder(f).Decode(&index); err != nil {
		return nil, xerrors.Errorf("unable to decode the index file: %w", err)
	}

	return &index, nil
}

func truncateString(str string, num int) string {
	if len(str) <= num {
		return str
	}
	return str[:num-3] + "..."
}
