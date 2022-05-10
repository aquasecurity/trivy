package version

type ListItemStack []ListItem

// IsEmpty checks if stack is empty
func (s *ListItemStack) IsEmpty() bool {
	return len(*s) == 0
}

// Push pushes a new value onto the stack
func (s *ListItemStack) Push(item ListItem) {
	*s = append(*s, item) // Simply append the new value to the end of the stack
}

// Pop removes and returns top element of stack. Return false if stack is empty.
func (s *ListItemStack) Pop() ListItem {
	if s.IsEmpty() {
		return nil
	}

	ss := *s
	index := len(ss) - 1
	element := (ss)[index]
	*s = ss[:index]
	return element
}
