package terraform

type Blocks []*Block

func (blocks Blocks) OfType(t string) Blocks {
	var results []*Block
	for _, block := range blocks {
		if block.Type() == t {
			results = append(results, block)
		}
	}
	return results
}

func (blocks Blocks) WithID(id string) *Block {
	for _, block := range blocks {
		if block.ID() == id {
			return block
		}
	}
	return nil
}
