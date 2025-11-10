package parser

import (
	"sort"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func sortBlocksByHierarchy(blocks terraform.Blocks) {
	c := &counter{
		cache: make(map[string]int),
	}
	sort.Slice(blocks, func(i, j int) bool {
		a := blocks[i]
		b := blocks[j]
		iDepth, jDepth := c.countBlockRecursion(a, blocks, 0), c.countBlockRecursion(b, blocks, 0)
		switch {
		case iDepth < jDepth:
			return true
		case iDepth > jDepth:
			return false
		default:
			return blocks[i].FullName() < blocks[j].FullName()
		}
	})
}

type counter struct {
	cache map[string]int
}

func (c *counter) countBlockRecursion(block *terraform.Block, blocks terraform.Blocks, count int) int {
	metadata := block.GetMetadata()
	if cached, ok := c.cache[metadata.Reference()]; ok {
		return cached
	}
	var maxCount int
	var hasRecursion bool
	for _, attrName := range []string{"for_each", "count"} {
		if attr := block.GetAttribute(attrName); attr.IsNotNil() {
			hasRecursion = true
			for _, other := range blocks {
				if attr.ReferencesBlock(other) {
					depth := c.countBlockRecursion(other, blocks, count)
					if depth > maxCount {
						maxCount = depth
					}
				}
			}
		}
	}
	if hasRecursion {
		maxCount++
	}
	result := maxCount + count
	c.cache[metadata.Reference()] = result
	return result
}
