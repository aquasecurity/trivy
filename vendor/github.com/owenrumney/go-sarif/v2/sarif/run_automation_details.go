package sarif

// RunAutomationDetails ...
type RunAutomationDetails struct {
	CorrelationGUID *string  `json:"correlationGuid,omitempty"`
	Description     *Message `json:"description,omitempty"`
	GUID            *string  `json:"guid,omitempty"`
	ID              *string  `json:"id,omitempty"`
	PropertyBag
}

// NewRunAutomationDetails ...
func NewRunAutomationDetails() *RunAutomationDetails {
	return &RunAutomationDetails{}
}

// WithCorrelationGUID sets the CorrelationGUID
func (runAutomationDetails *RunAutomationDetails) WithCorrelationGUID(correlationGUID string) *RunAutomationDetails {
	runAutomationDetails.CorrelationGUID = &correlationGUID
	return runAutomationDetails
}

// WithDescription sets the Message
func (runAutomationDetails *RunAutomationDetails) WithDescription(description *Message) *RunAutomationDetails {
	runAutomationDetails.Description = description
	return runAutomationDetails
}

// WithDescriptionText sets the Message text
func (runAutomationDetails *RunAutomationDetails) WithDescriptionText(text string) *RunAutomationDetails {
	if runAutomationDetails.Description == nil {
		runAutomationDetails.Description = &Message{}
	}
	runAutomationDetails.Description.Text = &text
	return runAutomationDetails
}

// WithDescriptionMarkdown sets the Message markdown
func (runAutomationDetails *RunAutomationDetails) WithDescriptionMarkdown(markdown string) *RunAutomationDetails {
	if runAutomationDetails.Description == nil {
		runAutomationDetails.Description = &Message{}
	}
	runAutomationDetails.Description.Markdown = &markdown
	return runAutomationDetails
}

// WithGUID sets the GUID
func (runAutomationDetails *RunAutomationDetails) WithGUID(guid string) *RunAutomationDetails {
	runAutomationDetails.GUID = &guid
	return runAutomationDetails
}

// WithID sets the ID
func (runAutomationDetails *RunAutomationDetails) WithID(id string) *RunAutomationDetails {
	runAutomationDetails.ID = &id
	return runAutomationDetails
}
