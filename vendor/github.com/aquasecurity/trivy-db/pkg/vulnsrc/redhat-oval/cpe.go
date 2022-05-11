package redhatoval

import "sort"

type CPEMap map[string]struct{}

func (m CPEMap) Add(cpe string) {
	m[cpe] = struct{}{}
}

func (m CPEMap) List() CPEList {
	var cpeList []string
	for cpe := range m {
		cpeList = append(cpeList, cpe)
	}
	sort.Strings(cpeList)
	return cpeList
}

type CPEList []string

func (l CPEList) Index(cpe string) int {
	for i, c := range l {
		if c == cpe {
			return i
		}
	}
	return -1
}

func (l CPEList) Indices(cpes []string) []int {
	var indices []int
	for _, cpe := range cpes {
		indices = append(indices, l.Index(cpe))
	}
	sort.Ints(indices)
	return indices
}
