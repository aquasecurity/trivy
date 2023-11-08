package vex

import (
	"slices"

	csaf "github.com/csaf-poc/csaf_distribution/v3/csaf"
)

// TODO: CSAF library should provide a function to find the pURL (or similar identifier, e.g. CPE)
// for a given product. Once that is available, we can remove this code.
// see https://github.com/csaf-poc/csaf_distribution/issues/484
func findProductsPURLs(advisory csaf.Advisory, products csaf.Products) []string {
	var productsPURLs []string
	for _, product := range products {
		if product == nil {
			continue
		}

		pURLsMap := findEveryProductPURLs(advisory)
		if pURLs, ok := pURLsMap[string(*product)]; ok {
			productsPURLs = append(productsPURLs, pURLs...)
		}
	}

	return productsPURLs
}

// findEveryProductPURLs returns a map of every product id to a list of purls
func findEveryProductPURLs(adv csaf.Advisory) map[string][]string {
	tree := adv.ProductTree
	if tree == nil {
		return nil
	}

	pURLsMap := make(map[string][]string)
	// If we have found it and we have a valid URL add unique.
	add := func(pid *csaf.ProductID, h *csaf.ProductIdentificationHelper) {
		if pid != nil && h != nil && h.PURL != nil {
			if _, ok := pURLsMap[string(*pid)]; !ok {
				pURLsMap[string(*pid)] = []string{string(*h.PURL)}
			} else {
				if !slices.Contains(pURLsMap[string(*pid)], string(*h.PURL)) {
					pURLsMap[string(*pid)] = append(pURLsMap[string(*pid)], string(*h.PURL))
				}
			}
		}
	}

	// First iterate over full product names.
	if names := tree.FullProductNames; names != nil {
		for _, name := range *names {
			if name != nil && name.ProductID != nil {
				add(name.ProductID, name.ProductIdentificationHelper)
			}
		}
	}

	// Second traverse the branches recursively.
	var recBranch func(*csaf.Branch)
	recBranch = func(b *csaf.Branch) {
		if p := b.Product; p != nil && p.ProductID != nil {
			add(p.ProductID, p.ProductIdentificationHelper)
		}
		for _, c := range b.Branches {
			recBranch(c)
		}
	}
	for _, b := range tree.Branches {
		recBranch(b)
	}

	return pURLsMap
}
