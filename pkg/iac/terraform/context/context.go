package context

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

type Context struct {
	ctx    *hcl.EvalContext
	parent *Context
}

func NewContext(ctx *hcl.EvalContext, parent *Context) *Context {
	if ctx.Variables == nil {
		ctx.Variables = make(map[string]cty.Value)
	}
	return &Context{
		ctx:    ctx,
		parent: parent,
	}
}

func (c *Context) NewChild() *Context {
	return NewContext(c.ctx.NewChild(), c)
}

func (c *Context) Parent() *Context {
	return c.parent
}

func (c *Context) Inner() *hcl.EvalContext {
	return c.ctx
}

func (c *Context) Root() *Context {
	root := c
	for root.Parent() != nil {
		root = root.Parent()
	}
	return root
}

func (c *Context) Get(parts ...string) cty.Value {
	if len(parts) == 0 {
		return cty.NilVal
	}

	curr := c.ctx.Variables[parts[0]]
	if len(parts) == 1 {
		return curr
	}

	for i, part := range parts[1:] {
		if !curr.Type().HasAttribute(part) {
			return cty.NilVal
		}

		attr := curr.GetAttr(part)

		if i == len(parts)-2 { // iteration from the first element
			return attr
		}

		if !(attr.IsKnown() && attr.Type().IsObjectType()) {
			return cty.NilVal
		}
		curr = attr
	}

	return cty.NilVal
}

func (c *Context) GetByDot(path string) cty.Value {
	return c.Get(strings.Split(path, ".")...)
}

func (c *Context) SetByDot(val cty.Value, path string) {
	c.Set(val, strings.Split(path, ".")...)
}

func (c *Context) Set(val cty.Value, parts ...string) {
	if len(parts) == 0 {
		return
	}

	v := mergeVars(c.ctx.Variables[parts[0]], parts[1:], val)
	c.ctx.Variables[parts[0]] = v
}

func (c *Context) Replace(val cty.Value, path string) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return
	}

	delete(c.ctx.Variables, parts[0])
	c.Set(val, parts...)
}

func mergeVars(src cty.Value, parts []string, value cty.Value) cty.Value {

	if len(parts) == 0 {
		if isNotEmptyObject(src) && isNotEmptyObject(value) {
			return mergeObjects(src, value)
		}
		return value
	}

	data := make(map[string]cty.Value)
	if isNotEmptyObject(src) {
		data = src.AsValueMap()
		if attr, ok := data[parts[0]]; ok {
			src = attr
		} else {
			src = cty.EmptyObjectVal
		}
	}

	data[parts[0]] = mergeVars(src, parts[1:], value)

	return cty.ObjectVal(data)
}

func mergeObjects(a, b cty.Value) cty.Value {
	output := make(map[string]cty.Value)

	for key, val := range a.AsValueMap() {
		output[key] = val
	}
	b.ForEachElement(func(key, val cty.Value) (stop bool) {
		k := key.AsString()
		old := output[k]
		if old.IsKnown() && isNotEmptyObject(old) && isNotEmptyObject(val) {
			output[k] = mergeObjects(old, val)
		} else {
			output[k] = val
		}
		return false
	})
	return cty.ObjectVal(output)
}

func isNotEmptyObject(val cty.Value) bool {
	return !val.IsNull() && val.IsKnown() && val.Type().IsObjectType() && val.LengthInt() > 0
}
