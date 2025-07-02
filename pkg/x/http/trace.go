package http

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	redactedText     = "<redacted>"
	binaryRedactText = "<binary data redacted>"
	maxBodySize      = 1024 * 1024 // 1MB

	// MIME types
	mimeApplicationJSON           = "application/json"
	mimeApplicationXML            = "application/xml"
	mimeApplicationFormURLEncoded = "application/x-www-form-urlencoded"
	mimeApplicationJavaScript     = "application/javascript"
	mimeApplicationOctetStream    = "application/octet-stream"
	mimeApplicationPDF            = "application/pdf"
	mimeApplicationZip            = "application/zip"
	mimeApplicationGzip           = "application/gzip"
	mimeApplicationXTar           = "application/x-tar"
	mimeApplicationXRar           = "application/x-rar"
	mimeMultipartFormData         = "multipart/form-data"
	mimeTextPrefix                = "text/"
	mimeImagePrefix               = "image/"
	mimeVideoPrefix               = "video/"
	mimeAudioPrefix               = "audio/"
	mimeApplicationVndPrefix      = "application/vnd."
)

var (
	// Colors for HTTP trace output
	requestHeaderColor  = color.New(color.FgCyan, color.Bold).SprintFunc()
	responseHeaderColor = color.New(color.FgGreen, color.Bold).SprintFunc()
	errorHeaderColor    = color.New(color.FgRed, color.Bold).SprintFunc()
	redactedColor       = color.New(color.FgYellow).SprintFunc()

	// HTTP method colors
	methodColor = color.New(color.FgMagenta, color.Bold).SprintFunc()
	urlColor    = color.New(color.FgBlue).SprintFunc()

	// Header colors
	headerKeyColor   = color.New(color.FgCyan).SprintFunc()
	headerValueColor = color.New(color.FgWhite).SprintFunc()

	// Status code colors
	statusSuccessColor  = color.New(color.FgGreen).SprintFunc()           // 2xx
	statusRedirectColor = color.New(color.FgYellow).SprintFunc()          // 3xx
	statusClientError   = color.New(color.FgRed).SprintFunc()             // 4xx
	statusServerError   = color.New(color.FgRed, color.Bold).SprintFunc() // 5xx

	// Sensitive headers that should be redacted
	sensitiveHeaders = []string{
		"Authorization",
		"Cookie",
		"Set-Cookie",
		"X-Auth-Token",
		"X-API-Key",
		"X-API-Secret",
		"X-Access-Token",
		"X-Secret-Key",
		"API-Key",
		"Access-Token",
		"Proxy-Authorization",
		"WWW-Authenticate",
		"X-CSRF-Token",
		"X-CSRFToken",
	}

	// Sensitive query parameters that should be redacted
	sensitiveQueryParams = []string{
		"token",
		"api_key",
		"apikey",
		"access_token",
		"client_secret",
		"secret",
		"password",
		"auth",
		"key",
		"session",
		"signature",
		"oauth_token",
	}
)

type traceTransport struct {
	inner  http.RoundTripper
	writer io.Writer
}

// TraceOption is a functional option for traceTransport
type TraceOption func(*traceTransport)

// WithWriter sets the writer for trace output
func WithWriter(w io.Writer) TraceOption {
	return func(tt *traceTransport) {
		tt.writer = w
	}
}

// NewTraceTransport returns an http.RoundTripper that logs HTTP requests and responses
func NewTraceTransport(inner http.RoundTripper, opts ...TraceOption) http.RoundTripper {
	tt := &traceTransport{
		inner:  inner,
		writer: os.Stderr, // default
	}

	for _, opt := range opts {
		opt(tt)
	}

	return tt
}

// RoundTrip implements http.RoundTripper with HTTP tracing
func (tt *traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Dump and redact request
	reqDump, err := dumpRequest(req)
	if err != nil {
		log.Debug("Failed to dump HTTP request", log.Err(err))
	}

	coloredDump := colorizeHTTPDump(reqDump, true)
	fmt.Fprintf(tt.writer, "\n%s\n%s\n", requestHeaderColor("--- HTTP REQUEST ---"), coloredDump)

	// Make the request
	resp, err := tt.inner.RoundTrip(req)
	if err != nil {
		fmt.Fprintf(tt.writer, "\n%s\n%v\n", errorHeaderColor("--- HTTP ERROR ---"), err)
		return nil, err
	} else if resp == nil {
		return nil, nil
	}

	// Dump and redact response
	respDump, err := dumpResponse(resp)
	if err != nil {
		log.Debug("Failed to dump HTTP response", log.Err(err))
	} else {
		coloredDump = colorizeHTTPDump(respDump, false)
		fmt.Fprintf(tt.writer, "\n%s\n%s\n", responseHeaderColor("--- HTTP RESPONSE ---"), coloredDump)
	}

	return resp, nil
}

// dumpRequest dumps and redacts sensitive information from the request
func dumpRequest(req *http.Request) (string, error) {
	// Clone request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Redact sensitive headers
	redactHeaders(reqClone.Header)

	// Redact sensitive query parameters
	if reqClone.URL != nil {
		reqClone.URL = redactQueryParams(reqClone.URL)
	}

	// Handle body
	if req.Body != nil && req.Body != http.NoBody {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return "", err
		}
		// Restore original body
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Set redacted body on clone
		redactedBody := redactBody(bodyBytes, req.Header.Get("Content-Type"))
		reqClone.Body = io.NopCloser(bytes.NewReader(redactedBody))
		reqClone.ContentLength = int64(len(redactedBody))
	}

	// Dump the redacted request
	dump, err := httputil.DumpRequestOut(reqClone, true)
	if err != nil {
		return "", err
	}

	return string(dump), nil
}

// dumpResponse dumps and redacts sensitive information from the response
func dumpResponse(resp *http.Response) (string, error) {
	// Read response body
	var bodyBytes []byte
	if resp.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		// Restore original body
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Clone response for redaction
	respClone := &http.Response{
		Status:           resp.Status,
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           resp.Header.Clone(),
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          resp.Trailer,
		Request:          resp.Request,
	}

	// Redact sensitive headers
	redactHeaders(respClone.Header)

	// Set redacted body
	if len(bodyBytes) > 0 {
		redactedBody := redactBody(bodyBytes, resp.Header.Get("Content-Type"))
		respClone.Body = io.NopCloser(bytes.NewReader(redactedBody))
		respClone.ContentLength = int64(len(redactedBody))
	}

	// Dump the redacted response
	dump, err := httputil.DumpResponse(respClone, true)
	if err != nil {
		return "", err
	}

	return string(dump), nil
}

// redactHeaders redacts sensitive headers
func redactHeaders(headers http.Header) {
	for _, header := range sensitiveHeaders {
		for k := range headers {
			if strings.EqualFold(k, header) {
				headers[k] = []string{redactedColor(redactedText)}
			}
		}
	}
}

// redactQueryParams redacts sensitive query parameters
func redactQueryParams(u *url.URL) *url.URL {
	// Clone URL to avoid modifying the original
	cloned, _ := url.Parse(u.String())

	values := cloned.Query()
	for _, param := range sensitiveQueryParams {
		for k := range values {
			if strings.EqualFold(k, param) {
				values[k] = []string{redactedColor(redactedText)}
			}
		}
	}
	cloned.RawQuery = values.Encode()

	return cloned
}

// redactBody redacts sensitive information from request/response bodies
func redactBody(body []byte, contentType string) []byte {
	// Check if body is too large
	if len(body) > maxBodySize {
		return []byte(fmt.Sprintf("<body too large: %d bytes>", len(body)))
	}

	// Check if body is binary
	if isBinaryContent(contentType) || isBinaryData(body) {
		return []byte(redactedColor(binaryRedactText))
	}

	// Redact sensitive patterns in text content
	redacted := string(body)

	// Handle JSON patterns
	jsonPattern := regexp.MustCompile(`(?i)"(password|passwd|pwd|secret|token|api_key|apikey|access_token|client_secret|auth_token|private_key)"\s*:\s*"[^"]*"`)
	redacted = jsonPattern.ReplaceAllStringFunc(redacted, func(match string) string {
		colonIndex := strings.Index(match, ":")
		if colonIndex != -1 {
			key := match[:colonIndex+1]
			return key + ` "` + redactedColor(redactedText) + `"`
		}
		return redactedColor(redactedText)
	})

	// Handle form data patterns
	formPattern := regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api_key|apikey|access_token|client_secret|auth_token|private_key)=[^&\s]+`)
	redacted = formPattern.ReplaceAllStringFunc(redacted, func(match string) string {
		equalIndex := strings.Index(match, "=")
		if equalIndex != -1 {
			key := match[:equalIndex+1]
			return key + redactedColor(redactedText)
		}
		return redactedColor(redactedText)
	})

	// Handle private keys
	privateKeyPattern := regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)
	redacted = privateKeyPattern.ReplaceAllString(redacted, redactedColor(redactedText))

	// Handle Bearer tokens
	bearerPattern := regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`)
	redacted = bearerPattern.ReplaceAllString(redacted, redactedColor(redactedText))

	return []byte(redacted)
}

// isBinaryContent checks if the content type indicates binary data
func isBinaryContent(contentType string) bool {
	if contentType == "" {
		return false
	}

	contentType = strings.ToLower(contentType)

	// Text-like content types (explicitly not binary)
	textTypes := []string{
		mimeTextPrefix,
		mimeApplicationJSON,
		mimeApplicationXML,
		mimeApplicationFormURLEncoded,
		mimeApplicationJavaScript,
		string(types.OCIContentDescriptor),
		string(types.OCIImageIndex),
		string(types.OCIManifestSchema1),
		string(types.OCIConfigJSON),
		string(types.DockerManifestSchema1),
		string(types.DockerManifestSchema1Signed),
		string(types.DockerManifestSchema2),
		string(types.DockerManifestList),
		string(types.DockerConfigJSON),
		string(types.DockerPluginConfig),
	}

	for _, textType := range textTypes {
		if strings.HasPrefix(contentType, textType) {
			return false
		}
	}

	// Common binary content types
	binaryTypes := []string{
		mimeApplicationOctetStream,
		mimeApplicationPDF,
		mimeApplicationZip,
		mimeApplicationGzip,
		mimeApplicationXTar,
		mimeApplicationXRar,
		mimeImagePrefix,
		mimeVideoPrefix,
		mimeAudioPrefix,
		mimeApplicationVndPrefix,
		mimeMultipartFormData,
	}

	for _, bType := range binaryTypes {
		if strings.HasPrefix(contentType, bType) {
			return true
		}
	}

	return false
}

// isBinaryData checks if the data appears to be binary using utils.IsBinary
func isBinaryData(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Use bytes.Reader to implement ReadSeekerAt interface
	reader := bytes.NewReader(data)

	isBinary, _ := utils.IsBinary(reader, int64(len(data)))
	return isBinary
}

// colorizeHTTPDump adds colors to HTTP request/response dumps
func colorizeHTTPDump(dump string, isRequest bool) string {
	lines := strings.Split(dump, "\n")
	if len(lines) == 0 {
		return dump
	}

	var result []string
	isBody := false

	for i, line := range lines {
		// Empty line indicates start of body
		if line == "" || line == "\r" {
			isBody = true
			result = append(result, line)
			continue
		}

		// First line processing
		if i == 0 {
			if isRequest {
				// Colorize request line: METHOD URL HTTP/1.1
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					coloredLine := fmt.Sprintf("%s %s %s",
						methodColor(parts[0]),
						urlColor(parts[1]),
						strings.Join(parts[2:], " "))
					result = append(result, coloredLine)
				} else {
					result = append(result, line)
				}
			} else {
				// Colorize response line: HTTP/1.1 STATUS_CODE STATUS_TEXT
				parts := strings.SplitN(line, " ", 3)
				if len(parts) >= 2 {
					statusCode := parts[1]
					statusColor := getStatusCodeColor(statusCode)
					coloredLine := fmt.Sprintf("%s %s",
						parts[0],
						statusColor(strings.Join(parts[1:], " ")))
					result = append(result, coloredLine)
				} else {
					result = append(result, line)
				}
			}
			continue
		}

		// Header processing
		if !isBody && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := parts[0]
				value := strings.TrimSpace(parts[1])
				// Don't color the value if it's already colored (e.g., redacted text)
				if strings.Contains(value, "\x1b[") {
					coloredLine := fmt.Sprintf("%s: %s",
						headerKeyColor(key),
						value)
					result = append(result, coloredLine)
				} else {
					coloredLine := fmt.Sprintf("%s: %s",
						headerKeyColor(key),
						headerValueColor(value))
					result = append(result, coloredLine)
				}
			} else {
				result = append(result, line)
			}
		} else {
			// Body content - no additional coloring
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

// getStatusCodeColor returns the appropriate color function for a status code
func getStatusCodeColor(statusCode string) func(...any) string {
	if len(statusCode) == 0 {
		return headerValueColor
	}

	switch statusCode[0] {
	case '2':
		return statusSuccessColor
	case '3':
		return statusRedirectColor
	case '4':
		return statusClientError
	case '5':
		return statusServerError
	default:
		return headerValueColor
	}
}
