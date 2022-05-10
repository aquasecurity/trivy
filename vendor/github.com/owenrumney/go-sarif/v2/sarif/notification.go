package sarif

import "time"

// Notification ...
type Notification struct {
	AssociatedRule *ReportingDescriptorReference `json:"associatedRule,omitempty"`
	Descriptor     *ReportingDescriptorReference `json:"descriptor,omitempty"`
	Exception      *Exception                    `json:"exception,omitempty"`
	Level          string                        `json:"level,omitempty"`
	Locations      []*Location                   `json:"locations,omitempty"`
	Message        *Message                      `json:"message"`
	ThreadID       *int                          `json:"threadId,omitempty"`
	TimeUTC        *time.Time                    `json:"timeUtc,omitempty"`
	PropertyBag
}

// NewNotification creates a new Notification and returns a pointer to it
func NewNotification() *Notification {
	return &Notification{}
}

// WithAssociatedRule sets the AssociatedRule
func (notification *Notification) WithAssociatedRule(associatedRule *ReportingDescriptorReference) *Notification {
	notification.AssociatedRule = associatedRule

	return notification
}

// WithDescriptor sets the Descriptor
func (notification *Notification) WithDescriptor(descriptor *ReportingDescriptorReference) *Notification {
	notification.Descriptor = descriptor

	return notification
}

// WithException sets the Exception
func (notification *Notification) WithException(exception *Exception) *Notification {
	notification.Exception = exception

	return notification
}

// WithLevel sets the Level
func (notification *Notification) WithLevel(level string) *Notification {
	notification.Level = level

	return notification
}

// WithLocations sets the Locations
func (notification *Notification) WithLocations(locations []*Location) *Notification {
	notification.Locations = locations

	return notification
}

// AddLocation ...
func (notification *Notification) AddLocation(location *Location) {
	notification.Locations = append(notification.Locations, location)
}

// WithMessage sets the Message
func (notification *Notification) WithMessage(message *Message) *Notification {
	notification.Message = message
	return notification
}

// WithTextMessage sets the Message text
func (notification *Notification) WithTextMessage(text string) *Notification {
	if notification.Message == nil {
		notification.Message = &Message{}
	}
	notification.Message.Text = &text
	return notification
}

// WithMessageMarkdown sets the Message markdown
func (notification *Notification) WithMessageMarkdown(markdown string) *Notification {
	if notification.Message == nil {
		notification.Message = &Message{}
	}
	notification.Message.Markdown = &markdown
	return notification
}

// WithThreadID sets the ThreadID
func (notification *Notification) WithThreadID(threadID int) *Notification {
	notification.ThreadID = &threadID

	return notification
}

// WithTimeUTC sets the TimeUTC
func (notification *Notification) WithTimeUTC(timeUTC *time.Time) *Notification {
	notification.TimeUTC = timeUTC
	return notification
}
