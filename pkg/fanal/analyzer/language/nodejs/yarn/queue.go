package yarn

type Item struct {
	id       string
	indirect bool
}

type Queue struct {
	items []Item
}

func newQueue() *Queue {
	return &Queue{}
}

func (q *Queue) enqueue(items ...Item) {
	q.items = append(q.items, items...)
}

func (q *Queue) dequeue() Item {
	item := q.items[0]
	q.items = q.items[1:]
	return item
}

func (q *Queue) isEmpty() bool {
	return len(q.items) == 0
}
