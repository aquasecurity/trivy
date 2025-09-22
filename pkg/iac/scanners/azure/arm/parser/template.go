package parser

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"strconv"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/resolver"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type MetadataReceiver interface {
	SetMetadata(*types.Metadata)
}

type Template struct {
	Metadata       *types.Metadata        `json:"-"`
	Schema         azure.Value            `json:"$schema"`
	ContentVersion azure.Value            `json:"contentVersion"`
	APIProfile     azure.Value            `json:"apiProfile"`
	Parameters     map[string]Parameter   `json:"parameters"`
	Variables      map[string]azure.Value `json:"variables"`
	Functions      []Function             `json:"functions"`
	Resources      Resources              `json:"resources"`
	Outputs        map[string]azure.Value `json:"outputs"`
}

type Parameter struct {
	Metadata     *types.Metadata
	Type         azure.Value `json:"type"`
	DefaultValue azure.Value `json:"defaultValue"`
	MaxLength    azure.Value `json:"maxLength"`
	MinLength    azure.Value `json:"minLength"`
}

type Function struct{}

type Resource struct {
	Metadata *types.Metadata `json:"-"`
	innerResource
}

func (t *Template) SetMetadata(m *types.Metadata) {
	t.Metadata = m
}

func (r *Resource) SetMetadata(m *types.Metadata) {
	r.Metadata = m
}

func (p *Parameter) SetMetadata(m *types.Metadata) {
	p.Metadata = m
}

type innerResource struct {
	APIVersion azure.Value `json:"apiVersion"`
	Type       azure.Value `json:"type"`
	Kind       azure.Value `json:"kind"`
	Name       azure.Value `json:"name"`
	Location   azure.Value `json:"location"`
	Tags       azure.Value `json:"tags"`
	Sku        azure.Value `json:"sku"`
	Properties azure.Value `json:"properties"`
	Resources  Resources   `json:"resources"`
}

// Resources is a collection of Resource items that can be represented in ARM
// templates either as an array or as a map (e.g., Bicep modules). This custom
// unmarshaler normalizes both forms into a flat slice.
type Resources []Resource

func (r *Resources) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	switch dec.PeekKind() {
	case '[':
		var arr []Resource
		if err := json.UnmarshalDecode(dec, &arr); err != nil {
			return err
		}
		*r = arr
	case '{':
		var m map[string]Resource
		if err := json.UnmarshalDecode(dec, &m); err != nil {
			return err
		}
		res := make([]Resource, 0, len(m))
		for _, v := range m {
			res = append(res, v)
		}
		*r = res
	case 'n':
		// null
		if err := json.UnmarshalDecode(dec, new(any)); err != nil {
			return err
		}
		*r = nil
	default:
		return errors.New("unexpected JSON token for resources")
	}
	return nil
}

func ParseTemplate(fsys fs.FS, path string) (*Template, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	lr := xjson.NewLineReader(bytes.NewReader(xjson.ToRFC8259(data)))

	mc := metadataCollector{
		path:    path,
		fsys:    fsys,
		entries: make(map[jsontext.Pointer]*types.Metadata),
	}

	var template Template
	if err := json.UnmarshalRead(lr, &template, json.WithUnmarshalers(
		xjson.UnmarshalerWithLocation[MetadataReceiver](lr, func() xjson.DecodeHook {
			return xjson.DecodeHook{
				After: mc.After,
			}
		}()),
	)); err != nil {
		return nil, fmt.Errorf("unmarshal template: %w", err)
	}
	mc.linkParentMetadata()

	rootMetadata := types.NewMetadata(
		types.NewRange(path, 0, 0, "", fsys),
		"",
	).WithInternal(resolver.NewResolver())
	template.Metadata.SetParentPtr(&rootMetadata)
	return &template, nil
}

type metadataCollector struct {
	path    string
	fsys    fs.FS
	entries map[jsontext.Pointer]*types.Metadata
}

func (c *metadataCollector) After(dec *jsontext.Decoder, obj any, loc ftypes.Location) {
	ptr := dec.StackPointer()
	ref := buildNodeRef(ptr.Tokens())
	rng := types.NewRange(c.path, loc.StartLine, loc.EndLine, "", c.fsys)

	md := types.NewMetadata(rng, ref)
	c.entries[ptr] = &md

	if r, ok := obj.(MetadataReceiver); ok {
		r.SetMetadata(&md)
	}
}

func (c *metadataCollector) linkParentMetadata() {
	for path, md := range c.entries {
		if md == nil || !isValidMetadata(md) {
			continue
		}
		parentPath, ok := c.findClosestValidParent(path)
		if !ok || parentPath == path {
			continue
		}
		md.SetParentPtr(c.entries[parentPath])
	}
}

func (c *metadataCollector) findClosestValidParent(path jsontext.Pointer) (jsontext.Pointer, bool) {
	for {
		path = path.Parent()
		if md, ok := c.entries[path]; ok && md != nil && isValidMetadata(md) {
			return path, true
		}
		if path == "" {
			return "", false
		}
	}
}

// The following helpers were used by the old map-based resources handling and
// are no longer needed as Resources.UnmarshalJSONFrom normalizes inputs.

func buildNodeRef(seq iter.Seq[string]) string {
	var sb strings.Builder
	for el := range seq {
		if _, err := strconv.Atoi(el); err == nil {
			sb.WriteString("[")
			sb.WriteString(el)
			sb.WriteString("]")
		} else {
			if sb.Len() > 0 {
				sb.WriteString(".")
			}
			sb.WriteString(el)
		}

	}
	return sb.String()
}

func isValidMetadata(m *types.Metadata) bool {
	rng := m.Range()
	return rng.GetStartLine() != 0 && rng.GetEndLine() != 0
}
