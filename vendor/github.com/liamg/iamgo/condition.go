package iamgo

import (
	"encoding/json"

	"github.com/liamg/jfather"
)

type Conditions struct {
	inner []Condition
	r     Range
}

type Condition struct {
	operator String
	key      String
	value    Strings
}

func (c *Conditions) UnmarshalJSONWithMetadata(node jfather.Node) error {
	var data map[string]map[string]Strings
	if err := node.Decode(&data); err != nil {
		return err
	}
	c.r = Range{
		StartLine: node.Range().Start.Line,
		EndLine:   node.Range().End.Line,
	}
	for operator, comparison := range data {
		for key, value := range comparison {
			value.r = c.r
			c.inner = append(c.inner, Condition{
				operator: String{
					inner: operator,
					r:     c.r,
				},
				key: String{
					inner: key,
					r:     c.r,
				},
				value: value,
			})
		}
	}
	return nil
}

func (c Conditions) MarshalJSON() ([]byte, error) {
	data := make(map[string]map[string]Strings)
	for _, condition := range c.inner {
		existing, ok := data[condition.operator.inner]
		if !ok {
			existing = make(map[string]Strings)
		}
		existing[condition.key.inner] = condition.value
		data[condition.operator.inner] = existing
	}
	return json.Marshal(data)
}

func (c *Condition) Operator() (string, Range) {
	return c.operator.inner, c.operator.r
}

func (c *Condition) Key() (string, Range) {
	return c.key.inner, c.key.r
}

func (c *Condition) Value() ([]string, Range) {
	return c.value.inner, c.value.r
}
