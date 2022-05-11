package sarif

// Stack ...
type Stack struct {
	Frames  []*StackFrame `json:"frames"`
	Message *Message      `json:"message,omitempty"`
	PropertyBag
}

// NewStack creates a new Stack and returns a pointer to it
func NewStack() *Stack {
	return &Stack{}
}

// WithFrames sets the Frames
func (stack *Stack) WithFrames(frames []*StackFrame) *Stack {
	stack.Frames = frames
	return stack
}

// AddFrame ...
func (stack *Stack) AddFrame(frame *StackFrame) {
	stack.Frames = append(stack.Frames, frame)
}

// WithMessage sets the Message
func (stack *Stack) WithMessage(message *Message) *Stack {
	stack.Message = message
	return stack
}

// WithTextMessage sets the Message text
func (stack *Stack) WithTextMessage(text string) *Stack {
	if stack.Message == nil {
		stack.Message = &Message{}
	}
	stack.Message.Text = &text
	return stack
}

// WithMessageMarkdown sets the Message markdown
func (stack *Stack) WithMessageMarkdown(markdown string) *Stack {
	if stack.Message == nil {
		stack.Message = &Message{}
	}
	stack.Message.Markdown = &markdown
	return stack
}
