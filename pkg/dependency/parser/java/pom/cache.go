package pom

import "fmt"

type pomCache map[string]*analysisResult

func newPOMCache() pomCache {
	return pomCache{}
}

func (c pomCache) put(art artifact, result analysisResult) {
	c[c.key(art)] = &result
}

func (c pomCache) get(art artifact) *analysisResult {
	return c[c.key(art)]
}

func (c pomCache) key(art artifact) string {
	return fmt.Sprintf("%s:%s", art.Name(), art.Version)
}
