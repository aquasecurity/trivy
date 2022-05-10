package sarif

// WebRequest ...
type WebRequest struct {
	Body       *ArtifactContent  `json:"body,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Index      *int              `json:"index,omitempty"`
	Method     *string           `json:"method,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	Protocol   *string           `json:"protocol,omitempty"`
	Target     *string           `json:"target,omitempty"`
	Version    *string           `json:"version,omitempty"`
	PropertyBag

}

// NewWebRequest creates a new WebRequest and returns a pointer to it
func NewWebRequest() *WebRequest {
	return &WebRequest{}
}

// WithBody sets the Body
func (webRequest *WebRequest) WithBody(body *ArtifactContent) *WebRequest {
	webRequest.Body = body
	return webRequest
}

// WithHeaders sets the Headers
func (webRequest *WebRequest) WithHeaders(headers map[string]string) *WebRequest {
	webRequest.Headers = headers
	return webRequest
}

// SetHeader ...
func (webRequest *WebRequest) SetHeader(name, value string) {
	webRequest.Headers[name] = value
}

// WithIndex sets the Index
func (webRequest *WebRequest) WithIndex(index int) *WebRequest {
	webRequest.Index = &index
	return webRequest
}

// WithMethod sets the Method
func (webRequest *WebRequest) WithMethod(method string) *WebRequest {
	webRequest.Method = &method
	return webRequest
}

// WithParameters sets the Parameters
func (webRequest *WebRequest) WithParameters(parameters map[string]string) *WebRequest {
	webRequest.Parameters = parameters
	return webRequest
}

// SetParameter ...
func (webRequest *WebRequest) SetParameter(name, value string) {
	webRequest.Parameters[name] = value
}

// WithProtocol sets the Protocol
func (webRequest *WebRequest) WithProtocol(protocol string) *WebRequest {
	webRequest.Protocol = &protocol
	return webRequest
}

// WithTarget sets the Target
func (webRequest *WebRequest) WithTarget(target string) *WebRequest {
	webRequest.Target = &target
	return webRequest
}

// WithVersion sets the Version
func (webRequest *WebRequest) WithVersion(version string) *WebRequest {
	webRequest.Version = &version
	return webRequest
}
