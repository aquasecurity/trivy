package sarif

// WebResponse ...
type WebResponse struct {
	Body               *ArtifactContent  `json:"body,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Index              *int              `json:"index,omitempty"`
	NoResponseReceived *bool             `json:"noResponseReceived,omitempty"`
	Protocol           *string           `json:"protocol,omitempty"`
	ReasonPhrase       *string           `json:"reasonPhrase,omitempty"`
	StatusCode         *int              `json:"statusCode,omitempty"`
	Version            *string           `json:"version,omitempty"`
	PropertyBag
}

// NewWebResponse creates a new WebResponse and returns a pointer to it
func NewWebResponse() *WebResponse {
	return &WebResponse{}
}

// WithBody sets the Body
func (webResponse *WebResponse) WithBody(body *ArtifactContent) *WebResponse {
	webResponse.Body = body
	return webResponse
}

// WithHeaders sets the Headers
func (webResponse *WebResponse) WithHeaders(headers map[string]string) *WebResponse {
	webResponse.Headers = headers
	return webResponse
}

// SetHeader ...
func (webResponse *WebResponse) SetHeader(name, value string) {
	webResponse.Headers[name] = value
}

// WithIndex sets the Index
func (webResponse *WebResponse) WithIndex(index int) *WebResponse {
	webResponse.Index = &index
	return webResponse
}

// WithNoResponseReceived sets the NoResponseReceived
func (webResponse *WebResponse) WithNoResponseReceived(noResponse bool) *WebResponse {
	webResponse.NoResponseReceived = &noResponse
	return webResponse
}

// WithProtocol sets the Protocol
func (webResponse *WebResponse) WithProtocol(protocol string) *WebResponse {
	webResponse.Protocol = &protocol
	return webResponse
}

// WithReasonPhrase sets the ReasonPhrase
func (webResponse *WebResponse) WithReasonPhrase(reason string) *WebResponse {
	webResponse.ReasonPhrase = &reason
	return webResponse
}

// WithStatusCode sets the StatusCode
func (webResponse *WebResponse) WithStatusCode(statusCode int) *WebResponse {
	webResponse.StatusCode = &statusCode
	return webResponse
}

// WithVersion sets the Version
func (webResponse *WebResponse) WithVersion(version string) *WebResponse {
	webResponse.Version = &version
	return webResponse
}
