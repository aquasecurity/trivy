package parser

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/go-ini/ini"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

type AnsibleConfig struct {
	Inventory string
}

func LoadConfig(fsys fs.FS, dir string) (AnsibleConfig, error) {
	// https://docs.ansible.com/ansible/latest/reference_appendices/config.html#the-configuration-file
	cfgPaths := []struct {
		path  string
		useOS bool
	}{
		{os.Getenv("ANSIBLE_CONFIG"), true},
		{path.Join(dir, "ansible.cfg"), false},
		{filepath.Join(fsutils.HomeDir(), ".ansible.cfg"), true},
		{"/etc/ansible/ansible.cfg", true},
	}

	for _, p := range cfgPaths {
		if p.path == "" {
			continue
		}

		var b []byte
		var err error

		if p.useOS {
			b, err = os.ReadFile(p.path)
		} else {
			b, err = fs.ReadFile(fsys, p.path)
		}

		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return AnsibleConfig{}, xerrors.Errorf("read file %q: %w", p.path, err)
		}

		cfg, err := parseConfig(b)
		if err != nil {
			return AnsibleConfig{}, xerrors.Errorf("parse config %q: %w", p.path, err)
		}
		return cfg, nil
	}

	return AnsibleConfig{}, nil
}

func parseConfig(b []byte) (AnsibleConfig, error) {
	// TODO: expand vars using os.ExpandEnv() ?
	f, err := ini.Load(b)
	if err != nil {
		return AnsibleConfig{}, xerrors.Errorf("load config file: %w", err)
	}

	cfg := AnsibleConfig{}

	section := f.Section("defaults")
	if k, err := section.GetKey("inventory"); err == nil {
		// TODO: trim spaces ?
		cfg.Inventory = k.String()
	}
	return cfg, nil
}
