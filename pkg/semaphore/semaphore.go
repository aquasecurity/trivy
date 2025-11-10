package semaphore

import "golang.org/x/sync/semaphore"

const defaultSize = 5

type Weighted = semaphore.Weighted

func New(parallel int) *Weighted {
	if parallel == 0 {
		parallel = defaultSize
	}
	return semaphore.NewWeighted(int64(parallel))
}
