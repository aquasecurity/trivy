package eval

import (
	"fmt"
	"sort"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

var NoInstanceData = InstanceData{}

type InstanceData struct {
	count     cty.Value
	eachKey   cty.Value
	eachValue cty.Value
}

type KeyInstanceType int

const (
	NoKeyType KeyInstanceType = iota
	StringKeyType
	IntKeyType
)

type nodeExpansion interface {
	Keys() (KeyInstanceType, []InstanceKey)
	Data(key InstanceKey) InstanceData
}

var ExpansionSingle = expansionSingle{}
var noKeys = []InstanceKey{NoKey}

type expansionSingle struct{}

func (e expansionSingle) Keys() (KeyInstanceType, []InstanceKey) {
	return NoKeyType, noKeys
}

func (e expansionSingle) Data(key InstanceKey) InstanceData {
	return NoInstanceData
}

type expansionCount int

func (e expansionCount) Keys() (KeyInstanceType, []InstanceKey) {
	keys := make([]InstanceKey, 0, e)
	for i := range e {
		keys = append(keys, IntKey(i))
	}
	return IntKeyType, keys
}

func (e expansionCount) Data(key InstanceKey) InstanceData {
	return InstanceData{
		count: cty.NumberIntVal(int64(key.(IntKey))),
	}
}

type expansionForEach map[string]cty.Value

func (e expansionForEach) Keys() (KeyInstanceType, []InstanceKey) {
	keys := make([]InstanceKey, 0, len(e))
	for k := range e {
		keys = append(keys, StringKey(k))
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].(StringKey) < keys[j].(StringKey)
	})
	return StringKeyType, keys
}

func (e expansionForEach) Data(key InstanceKey) InstanceData {
	k := string(key.(StringKey))
	v := e[k]
	return InstanceData{
		eachKey:   key.Value(),
		eachValue: v,
	}
}

func expandCount(countVal cty.Value) (int, error) {
	if countVal.IsNull() || !countVal.IsKnown() || countVal.Type() != cty.Number {
		return -1, fmt.Errorf("count is null, unkown or not a number")
	}
	count, _ := countVal.AsBigFloat().Int64()
	return int(count), nil
}

func expandForEach(forEachVal cty.Value) (map[string]cty.Value, error) {
	if forEachVal.IsNull() || !forEachVal.IsKnown() {
		return nil, fmt.Errorf("for-each is null or unkown")
	}
	if !forEachVal.CanIterateElements() {
		// TODO: log
		return nil, nil
	}

	data := make(map[string]cty.Value)
	it := forEachVal.ElementIterator()
	for it.Next() {
		key, val := it.Element()
		if key.IsNull() || !key.IsKnown() {
			continue
		}
		if val.IsNull() || !val.IsKnown() {
			continue
		}

		// TODO: tf allows only a map, or set of strings
		switch {
		case forEachVal.Type().IsSetType(), forEachVal.Type().IsListType(), forEachVal.Type().IsTupleType():
			key = val
		case forEachVal.Type().IsObjectType(), forEachVal.Type().IsMapType():
		default:
			return nil, nil
		}

		if key.Type() != cty.String {
			converted, err := convert.Convert(key, cty.String)
			if err != nil {
				continue
			}
			key = converted
		}
		data[key.AsString()] = val
	}
	return data, nil
}
