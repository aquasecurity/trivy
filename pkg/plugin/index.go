package plugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const indexURL = "https://aquasecurity.github.io/trivy-plugin-index/v1/index.yaml"

type Index struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Maintainer  string `yaml:"maintainer"`
	Description string `yaml:"description"`
	Repository  string `yaml:"repository"`
}

func (m *Manager) Update(ctx context.Context) error {
	m.logger.InfoContext(ctx, "Updating the plugin index...", log.String("url", m.indexURL))
	if err := downloader.Download(ctx, m.indexURL, filepath.Dir(m.indexPath), ""); err != nil {
		return xerrors.Errorf("unable to download the plugin index: %w", err)
	}
	return nil
}

func (m *Manager) Search(ctx context.Context, args []string) error {
	indexes, err := m.loadIndex()
	if errors.Is(err, os.ErrNotExist) {
		m.logger.ErrorContext(ctx, "The plugin index is not found. Please run 'trivy plugin update' to download the index.")
		return xerrors.Errorf("plugin index not found: %w", err)
	} else if err != nil {
		return xerrors.Errorf("unable to load the plugin index: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%-20s %-10s %-60s %-20s\n", "NAME", "TYPE", "DESCRIPTION", "MAINTAINER"))
	for _, index := range indexes {
		if len(args) == 0 || strings.Contains(index.Name, args[0]) || strings.Contains(index.Description, args[0]) {
			s := fmt.Sprintf("%-20s %-10s %-60s %-20s\n", truncateString(index.Name, 20), index.Type,
				truncateString(index.Description, 60), truncateString(index.Maintainer, 20))
			buf.WriteString(s)
		}
	}

	if _, err = fmt.Fprintf(m.w, buf.String()); err != nil {
		return err
	}

	return nil
}

// tryIndex returns the repository URL if the plugin name is found in the index.
// Otherwise, it returns the input name.
func (m *Manager) tryIndex(ctx context.Context, name string) string {
	// If the index file does not exist, download it first.
	if !fsutils.FileExists(m.indexPath) {
		if err := m.Update(ctx); err != nil {
			m.logger.ErrorContext(ctx, "Failed to update the plugin index", log.Err(err))
			return name
		}
	}

	indexes, err := m.loadIndex()
	if errors.Is(err, os.ErrNotExist) {
		m.logger.WarnContext(ctx, "The plugin index is not found. Please run 'trivy plugin update' to download the index.")
		return name
	} else if err != nil {
		m.logger.ErrorContext(ctx, "Unable to load the plugin index: %w", err)
		return name
	}

	for _, index := range indexes {
		if index.Name == name {
			return index.Repository
		}
	}
	return name
}

func (m *Manager) loadIndex() ([]Index, error) {
	f, err := os.Open(m.indexPath)
	if err != nil {
		return nil, xerrors.Errorf("unable to open the index file: %w", err)
	}
	defer f.Close()

	var indexes []Index
	if err = yaml.NewDecoder(f).Decode(&indexes); err != nil {
		return nil, xerrors.Errorf("unable to decode the index file: %w", err)
	}

	return indexes, nil
}

func truncateString(str string, num int) string {
	if len(str) <= num {
		return str
	}
	return str[:num-3] + "..."
}
