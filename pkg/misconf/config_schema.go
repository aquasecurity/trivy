package misconf

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"golang.org/x/xerrors"
)

type ConfigFileSchema struct {
	path   string
	name   string
	source []byte
	schema *jsonschema.Resolved
}

func LoadConfigSchemas(paths []string) ([]*ConfigFileSchema, error) {
	var configSchemas []*ConfigFileSchema
	for _, path := range paths {
		walkFn := func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
				return nil
			}

			schema, err := newConfigFileSchema(path)
			if err != nil {
				return xerrors.Errorf("load config file schema: %w", err)
			}

			configSchemas = append(configSchemas, schema)
			return nil
		}
		if err := filepath.WalkDir(path, walkFn); err != nil {
			return nil, xerrors.Errorf("walk error: %w", err)
		}
	}

	return configSchemas, nil
}

func newConfigFileSchema(path string) (*ConfigFileSchema, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, xerrors.Errorf("read config schema error: %w", err)
	}

	// Go's regular expression engine does not support \Z
	b = bytes.ReplaceAll(b, []byte(`\\Z`), []byte(`$`))

	// Go's regular expression engine does not support negative lookahead
	b = regexp.MustCompile(`\(\?\!.*\)`).ReplaceAll(b, []byte{})
	var s jsonschema.Schema
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, xerrors.Errorf("parse config schema %s error: %w", path, err)
	}
	schema, err := s.Resolve(nil)
	if err != nil {
		return nil, xerrors.Errorf("resolve config schema %s error: %w", path, err)
	}

	fileName := filepath.Base(path)
	schemaName := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	return &ConfigFileSchema{
		path:   path,
		name:   schemaName,
		schema: schema,
		source: b,
	}, nil
}
