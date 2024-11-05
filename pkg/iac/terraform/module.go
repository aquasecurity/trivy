package terraform

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/ignore"
)

type Module struct {
	blocks     Blocks
	blockMap   map[string]Blocks
	rootPath   string
	modulePath string
	ignores    ignore.Rules
	parent     *Module
}

func NewModule(rootPath, modulePath string, blocks Blocks, ignores ignore.Rules) *Module {

	blockMap := make(map[string]Blocks)

	for _, b := range blocks {
		if b.NameLabel() != "" {
			blockMap[b.TypeLabel()] = append(blockMap[b.TypeLabel()], b)
		}
	}

	return &Module{
		blocks:     blocks,
		ignores:    ignores,
		blockMap:   blockMap,
		rootPath:   rootPath,
		modulePath: modulePath,
	}
}

func (c *Module) SetParent(parent *Module) {
	c.parent = parent
}

func (c *Module) RootPath() string {
	return c.rootPath
}

func (c *Module) Ignores() ignore.Rules {
	return c.ignores
}

func (c *Module) GetBlocks() Blocks {
	return c.blocks
}

func (h *Module) GetBlocksByTypeLabel(typeLabel string) Blocks {
	return h.blockMap[typeLabel]
}

func (c *Module) getBlocksByType(blockType string, labels ...string) Blocks {
	if blockType == "module" {
		return c.getModuleBlocks()
	}
	var results Blocks
	for _, label := range labels {
		for _, block := range c.blockMap[label] {
			if block.Type() == blockType {
				results = append(results, block)
			}
		}
	}
	return results
}

func (c *Module) getModuleBlocks() Blocks {
	var results Blocks
	for _, block := range c.blocks {
		if block.Type() == "module" {
			results = append(results, block)
		}
	}
	return results
}

func (c *Module) GetResourcesByType(labels ...string) Blocks {
	return c.getBlocksByType("resource", labels...)
}

func (c *Module) GetResourcesByIDs(ids ...string) Blocks {
	var blocks Blocks

	for _, id := range ids {
		if block := c.blocks.WithID(id); block != nil {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

func (c *Module) GetDatasByType(label string) Blocks {
	return c.getBlocksByType("data", label)
}

func (c *Module) GetProviderBlocksByProvider(providerName, alias string) Blocks {
	var results Blocks
	for _, block := range c.blocks {
		if block.Type() == "provider" && len(block.Labels()) > 0 && block.TypeLabel() == providerName {
			if alias != "" {
				if block.HasChild("alias") && block.GetAttribute("alias").Equals(strings.ReplaceAll(alias, fmt.Sprintf("%s.", providerName), "")) {
					results = append(results, block)

				}
			} else if block.MissingChild("alias") {
				results = append(results, block)
			}
		}
	}
	return results
}

func (c *Module) GetReferencedBlock(referringAttr *Attribute, parentBlock *Block) (*Block, error) {
	for _, ref := range referringAttr.AllReferences() {
		if ref.TypeLabel() == "each" {
			if forEachAttr := parentBlock.GetAttribute("for_each"); forEachAttr.IsNotNil() {
				if b, err := c.GetReferencedBlock(forEachAttr, parentBlock); err == nil {
					return b, nil
				}
			}
		}
		for _, block := range c.blocks {
			if ref.RefersTo(block.reference) {
				return block, nil
			}
			kref := *ref
			kref.SetKey(parentBlock.reference.RawKey())
			if kref.RefersTo(block.reference) {
				return block, nil
			}
		}
	}
	return nil, fmt.Errorf("no referenced block found in '%s'", referringAttr.Name())
}

func (c *Module) GetBlockByID(id string) (*Block, error) {
	found := c.blocks.WithID(id)
	if found == nil {
		return nil, fmt.Errorf("no block found with id '%s'", id)
	}
	return found, nil
}

func (c *Module) GetReferencingResources(originalBlock *Block, referencingLabel, referencingAttributeName string) Blocks {
	return c.GetReferencingBlocks(originalBlock, "resource", referencingLabel, referencingAttributeName)
}

func (c *Module) GetsModulesBySource(moduleSource string) (Blocks, error) {
	var results Blocks

	modules := c.getModuleBlocks()
	for _, module := range modules {
		if module.HasChild("source") && module.GetAttribute("source").Equals(moduleSource) {
			results = append(results, module)
		}
	}
	return results, nil
}

func (c *Module) GetReferencingBlocks(originalBlock *Block, referencingType, referencingLabel, referencingAttributeName string) Blocks {
	blocks := c.getBlocksByType(referencingType, referencingLabel)
	var results Blocks
	for _, block := range blocks {
		attr := block.GetAttribute(referencingAttributeName)
		if attr == nil {
			continue
		}
		if attr.References(originalBlock.reference) {
			results = append(results, block)
		} else {
			for _, ref := range attr.AllReferences() {
				if ref.TypeLabel() == "each" {
					fe := block.GetAttribute("for_each")
					if fe.References(originalBlock.reference) {
						results = append(results, block)
					}
				}
			}
		}
	}
	return results
}
