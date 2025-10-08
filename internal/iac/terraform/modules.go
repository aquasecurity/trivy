package terraform

import (
	"errors"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

type Modules []*Module

type ResourceIDResolutions map[string]bool

func (r ResourceIDResolutions) Resolve(id string) {
	r[id] = true
}

func (r ResourceIDResolutions) Orphans() (orphanIDs []string) {
	for id, resolved := range r {
		if !resolved {
			orphanIDs = append(orphanIDs, id)
		}
	}
	return orphanIDs
}

func (m Modules) GetDatasByType(typeLabel string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetDatasByType(typeLabel)...)
	}

	return blocks
}

func (m Modules) GetResourcesByType(typeLabel ...string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetResourcesByType(typeLabel...)...)
	}

	return blocks
}

func (m Modules) GetChildResourceIDMapByType(typeLabels ...string) ResourceIDResolutions {
	blocks := m.GetResourcesByType(typeLabels...)

	idMap := make(map[string]bool)
	for _, block := range blocks {
		idMap[block.ID()] = false
	}

	return idMap
}

func (m Modules) GetReferencedBlock(referringAttr *Attribute, parentBlock *Block) (*Block, error) {
	var bestMatch *Block
	for _, module := range m {
		b, err := module.GetReferencedBlock(referringAttr, parentBlock)
		if err == nil {
			if bestMatch == nil || b.moduleBlock == parentBlock.moduleBlock {
				bestMatch = b
			}
		}
	}
	if bestMatch != nil {
		return bestMatch, nil
	}
	return nil, errors.New("block not found")
}

func (m Modules) GetReferencingResources(originalBlock *Block, referencingLabel, referencingAttributeName string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetReferencingResources(originalBlock, referencingLabel, referencingAttributeName)...)
	}

	return blocks
}

func (m Modules) GetBlocks() Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetBlocks()...)
	}
	return blocks
}

func (m Modules) GetBlockById(id string) (*Block, error) {
	for _, module := range m {
		if found := module.blocks.WithID(id); found != nil {
			return found, nil
		}

	}
	return nil, errors.New("block not found")
}

func (m Modules) GetResourceByIDs(id ...string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetResourcesByIDs(id...)...)
	}

	return blocks
}

func (m Modules) GetBlockByIgnoreRange(blockMetadata *types.Metadata) *Block {
	for _, module := range m {
		for _, block := range module.GetBlocks() {
			metadata := block.GetMetadata()
			if blockMetadata.Reference() == metadata.Reference() {
				return block
			}
		}
	}
	return nil
}
