package terraform

import (
	"fmt"
	"time"

	"github.com/zclconf/go-cty/cty"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Ignore struct {
	Range     iacTypes.Range
	RuleID    string
	Expiry    *time.Time
	Workspace string
	Block     bool
	Params    map[string]string
}

type Ignores []Ignore

func (ignores Ignores) Covering(modules Modules, m iacTypes.Metadata, workspace string, ids ...string) *Ignore {
	for _, ignore := range ignores {
		if ignore.Covering(modules, m, workspace, ids...) {
			return &ignore
		}
	}
	return nil
}

func (ignore Ignore) Covering(modules Modules, m iacTypes.Metadata, workspace string, ids ...string) bool {
	if ignore.Expiry != nil && time.Now().After(*ignore.Expiry) {
		return false
	}
	if ignore.Workspace != "" && ignore.Workspace != workspace {
		return false
	}
	idMatch := ignore.RuleID == "*" || len(ids) == 0
	for _, id := range ids {
		if id == ignore.RuleID {
			idMatch = true
			break
		}
	}
	if !idMatch {
		return false
	}

	metaHierarchy := &m
	for metaHierarchy != nil {
		if ignore.Range.GetFilename() != metaHierarchy.Range().GetFilename() {
			metaHierarchy = metaHierarchy.Parent()
			continue
		}
		if metaHierarchy.Range().GetStartLine() == ignore.Range.GetStartLine()+1 || metaHierarchy.Range().GetStartLine() == ignore.Range.GetStartLine() {
			return ignore.MatchParams(modules, metaHierarchy)
		}
		metaHierarchy = metaHierarchy.Parent()
	}
	return false

}

func (ignore Ignore) MatchParams(modules Modules, blockMetadata *iacTypes.Metadata) bool {
	if len(ignore.Params) == 0 {
		return true
	}
	block := modules.GetBlockByIgnoreRange(blockMetadata)
	if block == nil {
		return true
	}
	for key, param := range ignore.Params {
		val := block.GetValueByPath(key)
		switch val.Type() {
		case cty.String:
			if val.AsString() != param {
				return false
			}
		case cty.Number:
			bf := val.AsBigFloat()
			f64, _ := bf.Float64()
			comparableInt := fmt.Sprintf("%d", int(f64))
			comparableFloat := fmt.Sprintf("%f", f64)
			if param != comparableInt && param != comparableFloat {
				return false
			}
		case cty.Bool:
			if fmt.Sprintf("%t", val.True()) != param {
				return false
			}
		default:
			return false
		}
	}
	return true
}
